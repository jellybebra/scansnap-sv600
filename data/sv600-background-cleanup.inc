typedef struct {
  uint32_t *items;
  size_t capacity;
  size_t head;
  size_t count;
} SV600_Pixel_Queue;

static int
sv600_pixel_queue_push(SV600_Pixel_Queue *queue, uint32_t value,
                       size_t maximum)
{
  if (queue->count == queue->capacity) {
    size_t new_capacity = queue->capacity < maximum / 2
      ? queue->capacity * 2 : maximum;
    uint32_t *new_items;
    size_t first;

    if (new_capacity <= queue->capacity)
      return 0;
    new_items = malloc(new_capacity * sizeof(*new_items));
    if (!new_items)
      return 0;
    first = min(queue->count, queue->capacity - queue->head);
    memcpy(new_items, queue->items + queue->head,
           first * sizeof(*new_items));
    memcpy(new_items + first, queue->items,
           (queue->count - first) * sizeof(*new_items));
    free(queue->items);
    queue->items = new_items;
    queue->capacity = new_capacity;
    queue->head = 0;
  }

  queue->items[(queue->head + queue->count) % queue->capacity] = value;
  queue->count++;
  return 1;
}

static uint32_t
sv600_pixel_queue_pop(SV600_Pixel_Queue *queue)
{
  uint32_t value = queue->items[queue->head];
  queue->head++;
  if (queue->head == queue->capacity)
    queue->head = 0;
  queue->count--;
  return value;
}

static int
sv600_is_edge_background(const unsigned char *pixel, int dark_threshold,
                         int color_threshold)
{
  int high = max(pixel[0], max(pixel[1], pixel[2]));
  int low = min(pixel[0], min(pixel[1], pixel[2]));
  int luminance = (77 * pixel[0] + 150 * pixel[1] + 29 * pixel[2]) >> 8;

  return luminance < dark_threshold
    || (high - low > 25 && luminance < color_threshold);
}

static int
sv600_is_background_core(const unsigned char *pixels, int stride,
                         int width, int height, size_t index,
                         int dark_threshold, int color_threshold, int radius)
{
  size_t y;
  size_t x;
  const unsigned char *pixel;

  y = index / (size_t)width;
  x = index - y * (size_t)width;
  if (x < (size_t)radius || y < (size_t)radius
      || x + radius >= (size_t)width || y + radius >= (size_t)height)
    return 0;
  pixel = pixels + y * (size_t)stride + x * 3;
  return sv600_is_edge_background(pixel, dark_threshold, color_threshold)
    && sv600_is_edge_background(pixel - radius * 3, dark_threshold,
                                color_threshold)
    && sv600_is_edge_background(pixel + radius * 3, dark_threshold,
                                color_threshold)
    && sv600_is_edge_background(pixel - (size_t)radius * stride,
                                dark_threshold, color_threshold)
    && sv600_is_edge_background(pixel + (size_t)radius * stride,
                                dark_threshold, color_threshold);
}

static int
sv600_queue_background_core(const unsigned char *pixels, int stride,
                            int width, int height, size_t index,
                            int dark_threshold, int color_threshold, int radius,
                            unsigned char *connected,
                            SV600_Pixel_Queue *queue, size_t maximum)
{
  if (connected[index])
    return 1;
  if (!sv600_is_background_core(pixels, stride, width, height, index,
                                dark_threshold, color_threshold, radius))
    return 1;
  if (!sv600_pixel_queue_push(queue, (uint32_t)index, maximum))
    return 0;
  connected[index] = 1;
  return 1;
}

/* This is deliberately applied after the byte-exact factory finishing stage.
 * ScanSnap Home leaves table pixels in fixed A3L/A4L/A5L frames whenever the
 * paper does not cover the complete manufacturer rectangle.  Preserve that
 * geometry, but replace only dark or distinctly coloured print-consuming
 * pixels connected to an outside edge with RGB white.  Connectivity propagates
 * through an eroded, physically wide background core; thin writing and rules
 * therefore cannot carry it across a page.  Neutral paper shadows are also a
 * barrier, so marks such as the near-corner Z remain isolated from the table.
 * If the component grows beyond 5/8 of the frame, leave the image untouched;
 * this protects dark or coloured originals that do not look like white paper.
 */
static SANE_Status
buffer_sv600_whiten_edge_background(struct fujitsu *s, int side)
{
  SANE_Parameters *params = &s->s_params;
  int width = params->pixels_per_line;
  int height = params->lines;
  int stride = params->bytes_per_line;
  unsigned char *pixels = s->buffers[side];
  size_t histogram[256] = { 0 };
  size_t pixel_count;
  size_t percentile_target;
  size_t cumulative = 0;
  size_t connected_count = 0;
  size_t connected_limit;
  unsigned char *connected;
  SV600_Pixel_Queue queue = { NULL, 0, 0, 0 };
  int paper_peak = 255;
  int dark_threshold;
  int color_threshold;
  int radius;
  int rim;
  int expansion;
  int y;
  int x;

  if (params->format != SANE_FRAME_RGB || params->depth != 8
      || width < 2 || height < 2 || stride < width * 3
      || (size_t)width > UINT32_MAX / (size_t)height)
    return SANE_STATUS_INVAL;
  pixel_count = (size_t)width * height;

  for (y = 0; y < height; y++) {
    const unsigned char *pixel = pixels + (size_t)y * stride;
    for (x = 0; x < width; x++, pixel += 3) {
      int luminance =
        (77 * pixel[0] + 150 * pixel[1] + 29 * pixel[2]) >> 8;
      histogram[luminance]++;
    }
  }
  percentile_target = (pixel_count * 95 + 99) / 100;
  for (paper_peak = 0; paper_peak < 256; paper_peak++) {
    cumulative += histogram[paper_peak];
    if (cumulative >= percentile_target)
      break;
  }
  dark_threshold = paper_peak - 95;
  if (dark_threshold < 128)
    dark_threshold = 128;
  else if (dark_threshold > 160)
    dark_threshold = 160;
  color_threshold = paper_peak - 35;
  if (color_threshold < 180)
    color_threshold = 180;
  else if (color_threshold > 220)
    color_threshold = 220;
  radius = max(2, s->resolution_x / 100);
  rim = 2;
  if (width <= radius * 2 || height <= radius * 2)
    return SANE_STATUS_GOOD;

  connected = calloc(pixel_count, 1);
  queue.capacity = min(pixel_count, (size_t)(width + height) * 2);
  if (queue.capacity < 1024)
    queue.capacity = min(pixel_count, (size_t)1024);
  queue.items = malloc(queue.capacity * sizeof(*queue.items));
  if (!connected || !queue.items) {
    DBG (5, "buffer_sv600_whiten_edge_background: no memory, skipped\n");
    free(connected);
    free(queue.items);
    return SANE_STATUS_GOOD;
  }

#define SV600_QUEUE_BACKGROUND(index)                                      \
  do {                                                                     \
    size_t before = queue.count;                                           \
    if (!sv600_queue_background_core(pixels, stride, width, height,        \
                                     (index), dark_threshold,              \
                                     color_threshold, radius, connected,   \
                                     &queue, pixel_count)) {               \
      DBG (5, "buffer_sv600_whiten_edge_background: queue full, skipped\n"); \
      free(connected);                                                     \
      free(queue.items);                                                   \
      return SANE_STATUS_GOOD;                                             \
    }                                                                      \
    if (queue.count > before)                                              \
      connected_count++;                                                   \
  } while (0)

  for (x = radius; x < width - radius; x++) {
    SV600_QUEUE_BACKGROUND((size_t)radius * width + x);
    SV600_QUEUE_BACKGROUND((size_t)(height - 1 - radius) * width + x);
  }
  for (y = radius + 1; y < height - 1 - radius; y++) {
    SV600_QUEUE_BACKGROUND((size_t)y * width + radius);
    SV600_QUEUE_BACKGROUND((size_t)y * width + width - 1 - radius);
  }

  connected_limit = pixel_count * 5 / 8;
  while (queue.count) {
    size_t index = sv600_pixel_queue_pop(&queue);
    size_t row = index / (size_t)width;
    size_t column = index - row * (size_t)width;

    if (connected_count > connected_limit) {
      DBG (10, "buffer_sv600_whiten_edge_background: %.1f%% exceeds "
           "safety limit, skipped\n",
           100.0 * connected_count / pixel_count);
      free(connected);
      free(queue.items);
      return SANE_STATUS_GOOD;
    }
    if (column)
      SV600_QUEUE_BACKGROUND(index - 1);
    if (column + 1 < (size_t)width)
      SV600_QUEUE_BACKGROUND(index + 1);
    if (row)
      SV600_QUEUE_BACKGROUND(index - width);
    if (row + 1 < (size_t)height)
      SV600_QUEUE_BACKGROUND(index + width);
  }
#undef SV600_QUEUE_BACKGROUND

  /* Grow the connected core back to its original boundary, but never farther
   * than the erosion radius.  A thin line touching the crop edge can lose at
   * most the tiny physical rim below; it cannot erase the rest of the line. */
  for (expansion = 2; expansion <= radius + 1; expansion++) {
    for (y = 0; y < height; y++) {
      const unsigned char *pixel = pixels + (size_t)y * stride;
      size_t index = (size_t)y * width;
      for (x = 0; x < width; x++, pixel += 3, index++) {
        int adjacent = 0;
        if (connected[index]
            || !sv600_is_edge_background(pixel, dark_threshold,
                                          color_threshold))
          continue;
        if (x && connected[index - 1]
            && connected[index - 1] < expansion)
          adjacent = 1;
        else if (x + 1 < width && connected[index + 1]
                 && connected[index + 1] < expansion)
          adjacent = 1;
        else if (y && connected[index - width]
                 && connected[index - width] < expansion)
          adjacent = 1;
        else if (y + 1 < height && connected[index + width]
                 && connected[index + width] < expansion)
          adjacent = 1;
        if (adjacent) {
          connected[index] = (unsigned char)expansion;
          connected_count++;
        }
      }
    }
  }

  /* Remove the SV600's penultimate black output column with a fixed two-pixel
   * technical rim.  Do not use it as a path into the rest of the image. */
  for (y = 0; y < height; y++) {
    size_t index = (size_t)y * width;
    for (x = 0; x < width; x++, index++) {
      if (y >= rim && y < height - rim && x >= rim && x < width - rim)
        continue;
      if (!connected[index]) {
        connected[index] = (unsigned char)(radius + 2);
        connected_count++;
      }
    }
  }

  if (connected_count > connected_limit) {
    DBG (10, "buffer_sv600_whiten_edge_background: %.1f%% exceeds "
         "safety limit after expansion, skipped\n",
         100.0 * connected_count / pixel_count);
    free(connected);
    free(queue.items);
    return SANE_STATUS_GOOD;
  }

  for (y = 0; y < height; y++) {
    unsigned char *pixel = pixels + (size_t)y * stride;
    size_t index = (size_t)y * width;
    for (x = 0; x < width; x++, pixel += 3, index++) {
      if (connected[index])
        pixel[0] = pixel[1] = pixel[2] = 255;
    }
  }

  DBG (10, "buffer_sv600_whiten_edge_background: peak=%d dark=%d color=%d "
       "radius=%d whitened=%.1f%%\n", paper_peak, dark_threshold,
       color_threshold, radius,
       100.0 * connected_count / pixel_count);
  free(connected);
  free(queue.items);
  return SANE_STATUS_GOOD;
}
