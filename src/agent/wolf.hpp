#pragma once

#include <cairo.h>

namespace bm {

// Draws the right half of a front-facing wolf's head as an intaglio carving:
// the shape is cut into whatever surface is already on the context, lit from
// the upper left, so it reads as relief rather than as a pasted-on logo.
//
// (x, y) is the top of the wolf's centre line -- the muzzle points straight
// down from there and the head only extends to the right, so the caller should
// place x exactly on the blue rule. The head is authored for w around 0.75 * h;
// stray far from that and the proportions stop looking lupine.
void draw_carved_wolf(cairo_t* cr, double x, double y, double w, double h,
                      double strength);

// The same silhouette without the carving pass, for icons and previews.
void wolf_silhouette_path(cairo_t* cr, double x, double y, double w, double h);

} // namespace bm
