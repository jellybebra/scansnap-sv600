/* Research harness for the original 32-bit bookbound.dll.
 *
 * This program is intentionally not part of the Linux package.  It lets us
 * replay the two DLL calls made by ScanSnap Home against a P6 PPM image and
 * inspect their output while producing a native, redistributable equivalent.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BOOK_MODEL_BYTES 0x494af8
#define BOOK_PARAMETER_BYTES 0xd4

typedef int(__stdcall *load_book_parameter_fn)(void *parameters);
typedef int(__stdcall *auto_model_fn)(
  unsigned char *source, int width, int height, int stride, int depth, int dpi,
  void *input_points, void *book_model, void *parameters);
typedef int(__stdcall *content_correction_fn)(
  unsigned char *source, int width, int height, int stride, int depth, int dpi,
  void *book_model, unsigned char *destination, void *output_corners,
  void *parameters);

static int
read_number(FILE *stream, int *value)
{
  int character;

  do {
    character = fgetc(stream);
    if (character == '#') {
      do
        character = fgetc(stream);
      while (character != '\n' && character != EOF);
    }
  } while (character == ' ' || character == '\t' || character == '\r'
           || character == '\n');

  if (character < '0' || character > '9')
    return 0;
  *value = 0;
  do {
    *value = *value * 10 + character - '0';
    character = fgetc(stream);
  } while (character >= '0' && character <= '9');
  return character == ' ' || character == '\t' || character == '\r'
    || character == '\n';
}

static unsigned char *
read_ppm(const char *path, int *width, int *height)
{
  FILE *stream = fopen(path, "rb");
  unsigned char *pixels = NULL;
  int maximum;
  size_t bytes;

  if (!stream)
    return NULL;
  if (fgetc(stream) != 'P' || fgetc(stream) != '6'
      || !read_number(stream, width) || !read_number(stream, height)
      || !read_number(stream, &maximum) || maximum != 255
      || *width < 1 || *height < 1) {
    fclose(stream);
    return NULL;
  }
  bytes = (size_t)*width * (size_t)*height * 3;
  pixels = (unsigned char *)malloc(bytes);
  if (!pixels || fread(pixels, 1, bytes, stream) != bytes) {
    free(pixels);
    pixels = NULL;
  }
  fclose(stream);
  return pixels;
}

static int
write_ppm(const char *path, const unsigned char *pixels, int width, int height)
{
  FILE *stream = fopen(path, "wb");
  size_t bytes = (size_t)width * (size_t)height * 3;
  int ok;

  if (!stream)
    return 0;
  ok = fprintf(stream, "P6\n%d %d\n255\n", width, height) > 0
    && fwrite(pixels, 1, bytes, stream) == bytes;
  fclose(stream);
  return ok;
}

static int
write_blob(const char *path, const void *data, size_t bytes)
{
  FILE *stream = fopen(path, "wb");
  int ok;

  if (!stream)
    return 0;
  ok = fwrite(data, 1, bytes, stream) == bytes;
  fclose(stream);
  return ok;
}

int
main(int argc, char **argv)
{
  static const char load_name[] =
    "?LoadBookParameter@@YGHPAUBOK_CRR_PRM@@@Z";
  static const char auto_name[] =
    "?AutoBBLINEModelExtraction@@YGHPAEHHHHHPAUtagINPUT_POINTS@@"
    "PAUtagBOOK_MODEL@@PAUBOK_CRR_PRM@@@Z";
  static const char content_name[] =
    "?ContentModelCorrection@@YGHPAEHHHHHPAUtagBOOK_MODEL@@0"
    "PAUtagOUTPUT_CORNERS@@PAUBOK_CRR_PRM@@@Z";
  HMODULE library;
  load_book_parameter_fn load_parameters;
  auto_model_fn extract_model;
  content_correction_fn correct_content;
  unsigned char *source;
  unsigned char *destination;
  unsigned char *model;
  unsigned char input_points[0x48];
  unsigned char parameters[BOOK_PARAMETER_BYTES];
  int corners[12];
  double *curves[8];
  int width;
  int height;
  int result;
  int index;

  if (argc != 5) {
    fprintf(stderr, "usage: %s bookbound.dll input.ppm output.ppm dump-prefix\n",
            argv[0]);
    return 2;
  }
  source = read_ppm(argv[2], &width, &height);
  if (!source) {
    fprintf(stderr, "unable to read P6 PPM: %s\n", argv[2]);
    return 2;
  }
  destination = (unsigned char *)calloc((size_t)width * height, 3);
  model = (unsigned char *)calloc(1, BOOK_MODEL_BYTES);
  if (!destination || !model) {
    fprintf(stderr, "out of memory\n");
    return 2;
  }
  for (index = 0; index < 8; index++) {
    curves[index] = (double *)calloc((size_t)width, sizeof(double));
    if (!curves[index]) {
      fprintf(stderr, "out of memory\n");
      return 2;
    }
    memcpy(model + 0x30 + index * 4, &curves[index], sizeof(curves[index]));
  }

  library = LoadLibraryA(argv[1]);
  if (!library) {
    fprintf(stderr, "LoadLibrary failed: %lu\n", GetLastError());
    return 3;
  }
  load_parameters = (load_book_parameter_fn)GetProcAddress(library, load_name);
  extract_model = (auto_model_fn)GetProcAddress(library, auto_name);
  correct_content = (content_correction_fn)GetProcAddress(library, content_name);
  if (!load_parameters || !extract_model || !correct_content) {
    fprintf(stderr, "GetProcAddress failed: %lu (%p %p %p)\n", GetLastError(),
            load_parameters, extract_model, correct_content);
    return 3;
  }

  memset(input_points, 0, sizeof(input_points));
  memset(parameters, 0, sizeof(parameters));
  memset(corners, 0, sizeof(corners));
  result = load_parameters(parameters);
  *(int *)(parameters + 0xd0) = 1;
  fprintf(stderr, "LoadBookParameter=%d mode=%d\n", result,
          *(int *)(parameters + 0xd0));
  result = extract_model(source, width, height, width * 3, 24, 300,
                         input_points, model, parameters);
  fprintf(stderr, "AutoBBLINEModelExtraction=%d\n", result);
  if (result != 0)
    return 4;
  {
    char path[MAX_PATH];
    _snprintf(path, sizeof(path), "%s.auto.bin", argv[4]);
    if (!write_blob(path, model, BOOK_MODEL_BYTES)) {
      fprintf(stderr, "unable to write auto model: %s\n", path);
      return 6;
    }
  }
  result = correct_content(source, width, height, width * 3, 24, 300,
                           model, destination, corners, parameters);
  fprintf(stderr, "ContentModelCorrection=%d corners=", result);
  for (index = 0; index < 12; index++)
    fprintf(stderr, "%s%d", index ? "," : "", corners[index]);
  fputc('\n', stderr);
  if (result != 0)
    return 5;
  if (!write_ppm(argv[3], destination, width, height)) {
    fprintf(stderr, "unable to write output: %s\n", argv[3]);
    return 6;
  }
  if (!write_blob(argv[4], model, BOOK_MODEL_BYTES)) {
    fprintf(stderr, "unable to write model: %s\n", argv[4]);
    return 6;
  }
  for (index = 0; index < 8; index++) {
    char path[MAX_PATH];
    _snprintf(path, sizeof(path), "%s.curve%d.bin", argv[4], index);
    if (!write_blob(path, curves[index], (size_t)width * sizeof(double))) {
      fprintf(stderr, "unable to write curve: %s\n", path);
      return 6;
    }
  }

  FreeLibrary(library);
  return 0;
}
