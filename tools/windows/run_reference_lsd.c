/* Research wrapper for the peer-reviewed reference LSD implementation.
 *
 * Compile this file together with an independently obtained lsd.c.  The LSD
 * source is AGPL-3.0 and is deliberately not copied into this repository.
 */

#include "lsd.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int
main(int argc, char **argv)
{
  FILE *stream;
  unsigned char *bytes;
  double *image;
  double *segments;
  int width;
  int height;
  int count;
  int index;
  size_t pixels;

  if (argc != 5) {
    fprintf(stderr, "usage: %s width height input.raw output.bin\n", argv[0]);
    return 2;
  }
  width = atoi(argv[1]);
  height = atoi(argv[2]);
  pixels = (size_t)width * height;
  bytes = (unsigned char *)malloc(pixels);
  image = (double *)malloc(pixels * sizeof(*image));
  if (!bytes || !image)
    return 3;
  stream = fopen(argv[3], "rb");
  if (!stream || fread(bytes, 1, pixels, stream) != pixels)
    return 4;
  fclose(stream);
  for (index = 0; index < (int)pixels; index++)
    image[index] = bytes[index];
  free(bytes);

  segments = LineSegmentDetection(
    &count, image, width, height,
    0.5, 0.6, 2.0, 22.5, -1.0, 0.7, 1024,
    NULL, NULL, NULL);
  free(image);
  if (!segments)
    return 5;
  stream = fopen(argv[4], "wb");
  if (!stream)
    return 6;
  if (fwrite(&count, sizeof(count), 1, stream) != 1
      || fwrite(segments, sizeof(*segments), (size_t)count * 7, stream)
           != (size_t)count * 7)
    return 7;
  fclose(stream);
  free(segments);
  fprintf(stderr, "segments=%d\n", count);
  return 0;
}
