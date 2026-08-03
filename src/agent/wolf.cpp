#include "wolf.hpp"

#include <cmath>

namespace bm {

namespace {

// All geometry is authored in a unit box: u runs right from the centre line,
// v runs down from the top of the skull to the tip of the nose.
struct Frame {
    double x, y, w, h;
    double px(double u) const { return x + u * w; }
    double py(double v) const { return y + v * h; }
};

void curve(cairo_t* cr, const Frame& f, double c1u, double c1v, double c2u, double c2v,
           double u, double v) {
    cairo_curve_to(cr, f.px(c1u), f.py(c1v), f.px(c2u), f.py(c2v), f.px(u), f.py(v));
}

void line(cairo_t* cr, const Frame& f, double u, double v) {
    cairo_line_to(cr, f.px(u), f.py(v));
}

// The outline runs clockwise from the crown, out over the ear, down the angular
// cheek ruff, past the jaw, then back up the centre line along the muzzle.
void outline_path(cairo_t* cr, const Frame& f) {
    cairo_new_path(cr);
    cairo_move_to(cr, f.px(0.000), f.py(0.150));

    // Narrow forehead running out to the base of the ear. Keeping the crown
    // tight is what stops the head reading as an egg once it is mirrored.
    curve(cr, f, 0.090, 0.152, 0.192, 0.178, 0.248, 0.228);

    // Ear: straight leading edge up to the tip, softer curve down the back.
    line(cr, f, 0.508, 0.006);
    curve(cr, f, 0.598, 0.088, 0.648, 0.188, 0.652, 0.300);

    // Slight tuck behind the ear, then the cheek flares out to the ruff.
    curve(cr, f, 0.640, 0.348, 0.630, 0.368, 0.628, 0.392);
    curve(cr, f, 0.688, 0.442, 0.728, 0.488, 0.716, 0.532);

    // The ruff: three fur spikes, each notched back towards the jaw.
    line(cr, f, 0.784, 0.566);
    line(cr, f, 0.652, 0.598);
    line(cr, f, 0.742, 0.672);
    line(cr, f, 0.578, 0.700);
    line(cr, f, 0.636, 0.780);
    line(cr, f, 0.452, 0.782);

    // Lower jaw fur, then a notch that climbs back up so the snout in front of
    // it reads as a separate mass rather than part of the same lump.
    line(cr, f, 0.470, 0.876);
    curve(cr, f, 0.386, 0.862, 0.302, 0.826, 0.262, 0.752);

    // Side of the snout, dropping almost vertically, then a broad flat nose.
    // Bringing this to the centre line with a level tangent matters: a pointed
    // tip mirrors into a V and the whole head stops reading as a wolf.
    curve(cr, f, 0.258, 0.824, 0.252, 0.890, 0.248, 0.936);
    curve(cr, f, 0.242, 0.982, 0.160, 1.006, 0.000, 1.006);

    cairo_close_path(cr);
}

void inner_ear_path(cairo_t* cr, const Frame& f) {
    cairo_new_path(cr);
    cairo_move_to(cr, f.px(0.298), f.py(0.224));
    line(cr, f, 0.492, 0.074);
    curve(cr, f, 0.560, 0.152, 0.594, 0.230, 0.596, 0.298);
    cairo_close_path(cr);
}

// An angular almond that slants up towards the outside of the head, which is
// what makes the face read as a wolf rather than a dog.
void eye_path(cairo_t* cr, const Frame& f) {
    cairo_new_path(cr);
    cairo_move_to(cr, f.px(0.118), f.py(0.480));
    curve(cr, f, 0.216, 0.386, 0.330, 0.354, 0.412, 0.372);
    curve(cr, f, 0.352, 0.452, 0.236, 0.506, 0.132, 0.500);
    cairo_close_path(cr);
}

// The ridge along the top of the snout, mirroring the outer muzzle edge.
void muzzle_crease_path(cairo_t* cr, const Frame& f) {
    cairo_new_path(cr);
    cairo_move_to(cr, f.px(0.026), f.py(0.556));
    curve(cr, f, 0.106, 0.672, 0.158, 0.786, 0.176, 0.902);
}

void brow_path(cairo_t* cr, const Frame& f) {
    cairo_new_path(cr);
    cairo_move_to(cr, f.px(0.052), f.py(0.362));
    curve(cr, f, 0.190, 0.302, 0.362, 0.288, 0.474, 0.324);
}

// A short crease where the cheek ruff meets the jaw, to stop the lower half
// reading as one flat mass.
void cheek_path(cairo_t* cr, const Frame& f) {
    cairo_new_path(cr);
    cairo_move_to(cr, f.px(0.318), f.py(0.572));
    curve(cr, f, 0.404, 0.646, 0.436, 0.716, 0.418, 0.784);
}

// The nose pad: cut deepest of all, so the end of the snout has a focal point.
void nose_path(cairo_t* cr, const Frame& f) {
    cairo_new_path(cr);
    cairo_move_to(cr, f.px(0.000), f.py(0.914));
    curve(cr, f, 0.098, 0.920, 0.168, 0.948, 0.180, 0.972);
    curve(cr, f, 0.144, 0.998, 0.070, 1.008, 0.000, 1.008);
    cairo_close_path(cr);
}

using PathFn = void (*)(cairo_t*, const Frame&);

// One carved element: recess the fill slightly, darken the edge the light
// cannot reach, and catch the light on the opposite edge. Both bevel strokes
// are clipped to the shape so they stay inside it, which is what separates an
// engraving from an embossed sticker.
void carve(cairo_t* cr, const Frame& f, PathFn path, double strength, double depth,
           double bevel, bool fill_recess) {
    cairo_save(cr);
    path(cr, f);
    if (fill_recess) {
        cairo_set_source_rgba(cr, 0, 0, 0, 0.10 * depth * strength);
        cairo_fill_preserve(cr);
    }
    cairo_clip(cr);

    // Shadowed edge, up and to the left.
    cairo_save(cr);
    cairo_translate(cr, -bevel, -bevel);
    path(cr, f);
    cairo_set_line_width(cr, bevel * 1.9);
    cairo_set_line_join(cr, CAIRO_LINE_JOIN_ROUND);
    cairo_set_source_rgba(cr, 0, 0, 0, 0.38 * strength);
    cairo_stroke(cr);
    cairo_restore(cr);

    // Lit edge, down and to the right.
    cairo_save(cr);
    cairo_translate(cr, bevel, bevel);
    path(cr, f);
    cairo_set_line_width(cr, bevel * 1.7);
    cairo_set_line_join(cr, CAIRO_LINE_JOIN_ROUND);
    cairo_set_source_rgba(cr, 1, 1, 1, 0.34 * strength);
    cairo_stroke(cr);
    cairo_restore(cr);

    cairo_restore(cr);
}

// Creases are open paths, so they get a simple two-pass groove instead.
void carve_line(cairo_t* cr, const Frame& f, PathFn path, double strength, double width) {
    cairo_save(cr);
    cairo_set_line_cap(cr, CAIRO_LINE_CAP_ROUND);

    cairo_save(cr);
    cairo_translate(cr, -0.6, -0.6);
    path(cr, f);
    cairo_set_line_width(cr, width);
    cairo_set_source_rgba(cr, 0, 0, 0, 0.30 * strength);
    cairo_stroke(cr);
    cairo_restore(cr);

    cairo_save(cr);
    cairo_translate(cr, 0.7, 0.7);
    path(cr, f);
    cairo_set_line_width(cr, width);
    cairo_set_source_rgba(cr, 1, 1, 1, 0.26 * strength);
    cairo_stroke(cr);
    cairo_restore(cr);

    cairo_restore(cr);
}

} // namespace

void wolf_silhouette_path(cairo_t* cr, double x, double y, double w, double h) {
    Frame f{x, y, w, h};
    outline_path(cr, f);
}

void draw_carved_wolf(cairo_t* cr, double x, double y, double w, double h,
                      double strength) {
    Frame f{x, y, w, h};
    const double bevel = std::fmax(1.0, w * 0.011);

    carve(cr, f, outline_path, strength, 1.0, bevel, true);
    // The ear and eye are cut deeper than the head, so they still read at small
    // sizes where the outline bevel alone would flatten out.
    carve(cr, f, inner_ear_path, strength * 0.95, 2.0, bevel * 0.8, true);
    carve(cr, f, eye_path, strength, 3.2, bevel * 0.8, true);
    carve(cr, f, nose_path, strength, 3.0, bevel * 0.8, true);
    carve_line(cr, f, muzzle_crease_path, strength * 0.85, bevel * 1.2);
    carve_line(cr, f, brow_path, strength * 0.7, bevel * 1.0);
    carve_line(cr, f, cheek_path, strength * 0.55, bevel * 0.9);
}

} // namespace bm
