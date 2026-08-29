/* Replay the original SV600 document-geometry stages on a P6 PPM image.
 *
 * The helper deliberately loads the hash-pinned vendor DLLs at runtime.  The
 * SANE backend launches it as an isolated Wine child so the same P2IDIGCROP
 * and bookbound code used by ScanSnap Home performs the final geometry.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BOOK_MODEL_BYTES 0x494af8
#define BOOK_PARAMETER_BYTES 0xd4

typedef struct {
  unsigned char *pixels;
  int depth;
  int reserved0;
  int width;
  int height;
  int stride;
  int bytes;
  int x_dpi;
  int y_dpi;
  int reserved1;
  int reserved2;
  int last_x;
  int last_y;
} p2i_image;

typedef int(__stdcall *p2i_get_pos_fn)(p2i_image *source, int corners[8]);
typedef int(__stdcall *p2i_get_prm_fn)(
  p2i_image *source, p2i_image *destination, int corners[8]);
typedef int(__stdcall *p2i_crop_fn)(
  p2i_image *source, p2i_image *destination, int corners[8]);
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

static void
make_vendor_path(char path[MAX_PATH], const char *directory, const char *name)
{
  size_t length = strlen(directory);
  _snprintf(path, MAX_PATH, "%s%s%s", directory,
            length && (directory[length - 1] == '\\' || directory[length - 1] == '/')
              ? "" : "\\",
            name);
  path[MAX_PATH - 1] = '\0';
}

static void
describe_corners(const char *name, const int corners[8])
{
  fprintf(stderr,
          "%s=(%d,%d),(%d,%d),(%d,%d),(%d,%d)\n",
          name, corners[0], corners[1], corners[2], corners[3],
          corners[4], corners[5], corners[6], corners[7]);
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
  HMODULE p2i_library;
  HMODULE book_library;
  p2i_get_pos_fn get_pos;
  p2i_get_prm_fn get_prm;
  p2i_crop_fn crop;
  load_book_parameter_fn load_parameters;
  auto_model_fn extract_model;
  content_correction_fn correct_content;
  p2i_image source_image;
  p2i_image cropped_image;
  unsigned char *source;
  unsigned char *cropped;
  unsigned char *corrected;
  unsigned char *model;
  unsigned char input_points[0x48];
  unsigned char parameters[BOOK_PARAMETER_BYTES];
  int corners[8];
  int output_corners[12];
  double *curves[8];
  char path[MAX_PATH];
  int width;
  int height;
  int result;
  int index;

  if (argc != 5) {
    fprintf(stderr,
            "usage: %s vendor-dir input.ppm output.ppm a3|a4|a5|detect\n",
            argv[0]);
    return 2;
  }
  if (strcmp(argv[4], "a3") != 0 && strcmp(argv[4], "a4") != 0
      && strcmp(argv[4], "a5") != 0 && strcmp(argv[4], "detect") != 0) {
    fprintf(stderr, "unsupported geometry mode: %s\n", argv[4]);
    return 2;
  }

  source = read_ppm(argv[2], &width, &height);
  if (!source) {
    fprintf(stderr, "unable to read P6 PPM: %s\n", argv[2]);
    return 2;
  }

  make_vendor_path(path, argv[1], "P2IDIGCROP.dll");
  p2i_library = LoadLibraryA(path);
  if (!p2i_library) {
    fprintf(stderr, "P2IDIGCROP LoadLibrary failed: %lu (%s)\n",
            GetLastError(), path);
    return 3;
  }
  get_pos = (p2i_get_pos_fn)GetProcAddress(p2i_library, "P2iDigGetPos");
  get_prm = (p2i_get_prm_fn)GetProcAddress(p2i_library, "P2iDigGetPrm");
  crop = (p2i_crop_fn)GetProcAddress(p2i_library, "P2iDigCrop");
  if (!get_pos || !get_prm || !crop) {
    fprintf(stderr, "P2IDIGCROP GetProcAddress failed: %lu\n", GetLastError());
    return 3;
  }

  memset(&source_image, 0, sizeof(source_image));
  source_image.pixels = source;
  source_image.depth = 24;
  source_image.width = width;
  source_image.height = height;
  source_image.stride = width * 3;
  source_image.bytes = width * height * 3;
  source_image.x_dpi = 300;
  source_image.y_dpi = 300;
  source_image.last_x = -1;
  source_image.last_y = -1;

  if (strcmp(argv[4], "a3") == 0) {
    static const int a3_corners[8] = {
      430, 76, 5390, 76, 430, 3583, 5390, 3583
    };
    if (width != 5816 || height != 4352) {
      fprintf(stderr, "A3 boundary must be 5816x4352, got %dx%d\n",
              width, height);
      return 4;
    }
    memcpy(corners, a3_corners, sizeof(corners));
  }
  else if (strcmp(argv[4], "a4") == 0) {
    static const int a4_corners[8] = {
      1155, 76, 4662, 76, 1155, 2556, 4662, 2556
    };
    if (width != 5816 || height != 2781) {
      fprintf(stderr, "A4 boundary must be 5816x2781, got %dx%d\n",
              width, height);
      return 4;
    }
    memcpy(corners, a4_corners, sizeof(corners));
  }
  else if (strcmp(argv[4], "a5") == 0) {
    static const int a5_corners[8] = {
      1668, 76, 4148, 76, 1668, 1824, 4148, 1824
    };
    if (width != 5816 || height != 2781) {
      fprintf(stderr, "A5 boundary must be 5816x2781, got %dx%d\n",
              width, height);
      return 4;
    }
    memcpy(corners, a5_corners, sizeof(corners));
  }
  else {
    memset(corners, 0, sizeof(corners));
    result = get_pos(&source_image, corners);
    fprintf(stderr, "P2iDigGetPos=%d\n", result);
    if (result != 0)
      return 4;
  }
  {
    const char *override = getenv("SV600_CORNERS");
    if (override && *override) {
      if (sscanf(override, "%d,%d,%d,%d,%d,%d,%d,%d",
                 &corners[0], &corners[1], &corners[2], &corners[3],
                 &corners[4], &corners[5], &corners[6], &corners[7]) != 8) {
        fprintf(stderr, "invalid SV600_CORNERS: %s\n", override);
        return 2;
      }
    }
  }
  describe_corners("crop-corners", corners);

  memset(&cropped_image, 0, sizeof(cropped_image));
  result = get_prm(&source_image, &cropped_image, corners);
  fprintf(stderr, "P2iDigGetPrm=%d output=%dx%d stride=%d bytes=%d\n",
          result, cropped_image.width, cropped_image.height,
          cropped_image.stride, cropped_image.bytes);
  if (result != 0 || cropped_image.width < 1 || cropped_image.height < 1
      || cropped_image.stride < cropped_image.width * 3
      || cropped_image.bytes < cropped_image.stride * cropped_image.height)
    return 4;
  cropped = (unsigned char *)calloc(1, (size_t)cropped_image.bytes);
  corrected = (unsigned char *)calloc(1, (size_t)cropped_image.bytes);
  if (!cropped || !corrected) {
    fprintf(stderr, "out of memory for crop\n");
    return 2;
  }
  cropped_image.pixels = cropped;
  result = crop(&source_image, &cropped_image, corners);
  fprintf(stderr, "P2iDigCrop=%d\n", result);
  if (result != 0)
    return 4;
  {
    const char *debug_crop = getenv("SV600_DEBUG_CROP");
    if (debug_crop && *debug_crop
        && !write_ppm(debug_crop, cropped, cropped_image.width,
                      cropped_image.height)) {
      fprintf(stderr, "unable to write debug crop: %s\n", debug_crop);
      return 6;
    }
  }

  make_vendor_path(path, argv[1], "bookbound.dll");
  book_library = LoadLibraryA(path);
  if (!book_library) {
    fprintf(stderr, "bookbound LoadLibrary failed: %lu (%s)\n",
            GetLastError(), path);
    return 3;
  }
  load_parameters = (load_book_parameter_fn)GetProcAddress(book_library, load_name);
  extract_model = (auto_model_fn)GetProcAddress(book_library, auto_name);
  correct_content =
    (content_correction_fn)GetProcAddress(book_library, content_name);
  if (!load_parameters || !extract_model || !correct_content) {
    fprintf(stderr, "bookbound GetProcAddress failed: %lu\n", GetLastError());
    return 3;
  }

  model = (unsigned char *)calloc(1, BOOK_MODEL_BYTES);
  if (!model) {
    fprintf(stderr, "out of memory for book model\n");
    return 2;
  }
  for (index = 0; index < 8; index++) {
    curves[index] = (double *)calloc((size_t)cropped_image.width, sizeof(double));
    if (!curves[index]) {
      fprintf(stderr, "out of memory for book curve\n");
      return 2;
    }
    memcpy(model + 0x30 + index * 4, &curves[index], sizeof(curves[index]));
  }
  memset(input_points, 0, sizeof(input_points));
  memset(parameters, 0, sizeof(parameters));
  memset(output_corners, 0, sizeof(output_corners));
  result = load_parameters(parameters);
  *(int *)(parameters + 0xd0) = 1;
  fprintf(stderr, "LoadBookParameter=%d mode=%d\n", result,
          *(int *)(parameters + 0xd0));
  if (result != 0)
    return 5;
  result = extract_model(cropped, cropped_image.width, cropped_image.height,
                         cropped_image.stride, 24, 300, input_points, model,
                         parameters);
  fprintf(stderr, "AutoBBLINEModelExtraction=%d\n", result);
  if (result != 0)
    return 5;
  result = correct_content(cropped, cropped_image.width, cropped_image.height,
                           cropped_image.stride, 24, 300, model, corrected,
                           output_corners, parameters);
  fprintf(stderr, "ContentModelCorrection=%d\n", result);
  if (result != 0)
    return 5;

  if (!write_ppm(argv[3], corrected, cropped_image.width, cropped_image.height)) {
    fprintf(stderr, "unable to write output: %s\n", argv[3]);
    return 6;
  }
  FreeLibrary(book_library);
  FreeLibrary(p2i_library);
  return 0;
}
