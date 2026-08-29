/* Replay ScanSnap Home's P2IATRES resize operation on a packed RGB P6 PPM. */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

typedef int(__stdcall *p2i_get_resize_parameters_fn)(
  p2i_image *source, p2i_image *destination, int resolution);
typedef int(__stdcall *p2i_resize_fn)(
  p2i_image *source, p2i_image *destination);

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
            length && (directory[length - 1] == '\\'
                       || directory[length - 1] == '/') ? "" : "\\",
            name);
  path[MAX_PATH - 1] = '\0';
}

int
main(int argc, char **argv)
{
  HMODULE library;
  p2i_get_resize_parameters_fn get_parameters;
  p2i_resize_fn resize;
  p2i_image source_image;
  p2i_image destination_image;
  unsigned char *source;
  unsigned char *destination;
  char path[MAX_PATH];
  int width;
  int height;
  int resolution;
  int result;
  size_t bytes;

  if (argc != 5) {
    fprintf(stderr, "usage: %s vendor-dir input.ppm output.ppm resolution\n",
            argv[0]);
    return 2;
  }
  resolution = atoi(argv[4]);
  if (resolution < 1 || resolution > 1200)
    return 2;
  source = read_ppm(argv[2], &width, &height);
  if (!source)
    return 2;

  make_vendor_path(path, argv[1], "P2IATRES.DLL");
  library = LoadLibraryA(path);
  if (!library) {
    fprintf(stderr, "P2IATRES LoadLibrary failed: %lu (%s)\n",
            GetLastError(), path);
    return 3;
  }
  get_parameters = (p2i_get_resize_parameters_fn)GetProcAddress(
    library, "P2iGetResizePrm");
  resize = (p2i_resize_fn)GetProcAddress(library, "P2iResize");
  if (!get_parameters || !resize) {
    fprintf(stderr, "P2IATRES GetProcAddress failed: %lu\n", GetLastError());
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
  memset(&destination_image, 0, sizeof(destination_image));
  result = get_parameters(&source_image, &destination_image, resolution);
  fprintf(stderr,
          "P2iGetResizePrm=%08x output=%dx%d depth=%d dpi=%dx%d "
          "stride=%d bytes=%d\n",
          (unsigned int)result, destination_image.width,
          destination_image.height, destination_image.depth,
          destination_image.x_dpi, destination_image.y_dpi,
          destination_image.stride, destination_image.bytes);
  if (result != 0 || destination_image.width < 1
      || destination_image.height < 1 || destination_image.depth != 24
      || destination_image.stride < destination_image.width * 3
      || destination_image.bytes
           < destination_image.stride * destination_image.height)
    return 4;
  bytes = (size_t)destination_image.bytes;
  destination = (unsigned char *)calloc(1, bytes);
  if (!destination)
    return 2;
  destination_image.pixels = destination;
  result = resize(&source_image, &destination_image);
  fprintf(stderr, "P2iResize=%08x\n", (unsigned int)result);
  if (result != 0)
    return 4;
  if (!write_ppm(argv[3], destination, destination_image.width,
                 destination_image.height))
    return 5;
  FreeLibrary(library);
  free(destination);
  free(source);
  return 0;
}
