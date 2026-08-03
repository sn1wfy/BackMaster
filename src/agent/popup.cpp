#include "popup.hpp"

#include <cmath>

#include "bm/util.hpp"
#include "wolf.hpp"

namespace bm {

namespace {

// Panel geometry, in logical pixels.
constexpr double kRadius = 16.0;
constexpr double kBarWidth = 7.0;   // the blue rule down the left edge
constexpr double kWolfWidth = 196.0;
constexpr double kContentLeft = 208.0;

struct Rgb {
    double r, g, b;
};

Rgb severity_colour(Severity s) {
    switch (s) {
    case Severity::Critical: return {0.898, 0.271, 0.298};
    case Severity::High: return {0.949, 0.475, 0.114};
    case Severity::Medium: return {0.937, 0.784, 0.157};
    case Severity::Low: return {0.310, 0.706, 0.412};
    case Severity::Info: return {0.353, 0.596, 0.945};
    }
    return {0.353, 0.596, 0.945};
}

const char* severity_label(Severity s) {
    switch (s) {
    case Severity::Critical: return "CRITICAL";
    case Severity::High: return "HIGH RISK";
    case Severity::Medium: return "MEDIUM";
    case Severity::Low: return "LOW";
    case Severity::Info: return "INFO";
    }
    return "INFO";
}

void rounded_rect(cairo_t* cr, double x, double y, double w, double h, double r) {
    cairo_new_sub_path(cr);
    cairo_arc(cr, x + w - r, y + r, r, -G_PI / 2, 0);
    cairo_arc(cr, x + w - r, y + h - r, r, 0, G_PI / 2);
    cairo_arc(cr, x + r, y + h - r, r, G_PI / 2, G_PI);
    cairo_arc(cr, x + r, y + r, r, G_PI, 3 * G_PI / 2);
    cairo_close_path(cr);
}

std::string escape_markup(const std::string& s) {
    char* esc = g_markup_escape_text(s.c_str(), -1);
    std::string out = esc ? esc : s;
    g_free(esc);
    return out;
}

// Long paths and URLs would otherwise stretch the window; clip them in the middle
// where the interesting part is at both ends.
std::string elide(const std::string& s, size_t max_len) {
    if (s.size() <= max_len) return s;
    size_t head = max_len * 2 / 3;
    size_t tail = max_len - head - 3;
    return s.substr(0, head) + "..." + s.substr(s.size() - tail);
}

const char* kCss = R"CSS(
window.backmaster { background-color: transparent; }
.bm-title      { color: #ffffff; font-size: 15pt; font-weight: 700; }
.bm-brand      { color: rgba(255,255,255,0.62); font-size: 9pt;
                 font-weight: 700; letter-spacing: 2px; }
.bm-detail     { color: rgba(255,255,255,0.74); font-size: 10pt; }
.bm-key        { color: rgba(255,255,255,0.55); font-size: 10pt; }
.bm-value      { color: #ffffff; font-size: 10pt; }
.bm-note       { font-size: 9pt; }
.bm-note.ok    { color: #7ee2a0; }
.bm-note.error { color: #ff9c9c; }
.bm-chip       { font-size: 8pt; font-weight: 700; letter-spacing: 1px;
                 color: #ffffff; padding: 2px 9px; border-radius: 9px; }
.bm-chip.critical { background-color: rgba(229, 69, 76, 0.92); }
.bm-chip.high     { background-color: rgba(242,121, 29, 0.92); }
.bm-chip.medium   { background-color: rgba(239,200, 40, 0.92); color: #33291a; }
.bm-chip.low      { background-color: rgba( 79,180,105, 0.92); }
.bm-chip.info     { background-color: rgba( 90,152,241, 0.92); }

button.bm-x {
  background: transparent; border: none; box-shadow: none; min-width: 26px;
  min-height: 26px; padding: 0; color: rgba(255,255,255,0.70);
  font-size: 13pt; font-weight: 700;
}
button.bm-x:hover { background: rgba(255,255,255,0.14); border-radius: 13px;
                    color: #ffffff; }

button.bm-secondary {
  background: transparent; color: #ffffff; border: 1px solid rgba(255,255,255,0.42);
  border-radius: 17px; padding: 6px 22px; font-size: 10pt; font-weight: 600;
  box-shadow: none; text-shadow: none;
}
button.bm-secondary:hover { background: rgba(255,255,255,0.13);
                            border-color: rgba(255,255,255,0.70); }

button.bm-primary {
  background-image: linear-gradient(to bottom, #3b86f0, #1f5fd0);
  color: #ffffff; border: none; border-radius: 17px; padding: 6px 22px;
  font-size: 10pt; font-weight: 600; box-shadow: none; text-shadow: none;
}
button.bm-primary:hover {
  background-image: linear-gradient(to bottom, #4d93f5, #2a6ade);
}
button.bm-primary:disabled { opacity: 0.45; }
)CSS";

} // namespace

void popup_install_css() {
    static gboolean done = FALSE;
    if (done) return;
    done = TRUE;
    GtkCssProvider* p = gtk_css_provider_new();
    gtk_css_provider_load_from_string(p, kCss);
    gtk_style_context_add_provider_for_display(gdk_display_get_default(),
                                               GTK_STYLE_PROVIDER(p),
                                               GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(p);
}

void Popup::present(GtkApplication* app, const Alert& alert, const PopupStyle& style,
                    ExcludeFn on_exclude, ClosedFn on_closed) {
    // Deleted from on_destroy once GTK has finished with the window.
    auto* p = new Popup(app, alert, style, std::move(on_exclude), std::move(on_closed));
    p->build();
}

Popup::Popup(GtkApplication* app, const Alert& alert, const PopupStyle& style,
             ExcludeFn on_exclude, ClosedFn on_closed)
    : alert_(alert), style_(style), on_exclude_(std::move(on_exclude)),
      on_closed_(std::move(on_closed)), app_(app) {}

void Popup::on_draw(GtkDrawingArea* area, cairo_t* cr, int w, int h, gpointer data) {
    auto* self = static_cast<Popup*>(data);
    const double W = w, H = h;

    cairo_set_operator(cr, CAIRO_OPERATOR_SOURCE);
    cairo_set_source_rgba(cr, 0, 0, 0, 0);
    cairo_paint(cr);
    cairo_set_operator(cr, CAIRO_OPERATOR_OVER);

    // ---- the translucent grey panel ----
    rounded_rect(cr, 0, 0, W, H, kRadius);
    cairo_save(cr);
    cairo_clip_preserve(cr);

    cairo_pattern_t* grad = cairo_pattern_create_linear(0, 0, 0, H);
    const double a = self->style_.opacity;
    cairo_pattern_add_color_stop_rgba(grad, 0.0, 0.271, 0.283, 0.310, a);
    cairo_pattern_add_color_stop_rgba(grad, 1.0, 0.180, 0.188, 0.208, a);
    cairo_set_source(cr, grad);
    cairo_fill_preserve(cr);
    cairo_pattern_destroy(grad);

    // A soft sheen along the top edge keeps the panel from looking flat.
    cairo_pattern_t* sheen = cairo_pattern_create_linear(0, 0, 0, H * 0.4);
    cairo_pattern_add_color_stop_rgba(sheen, 0.0, 1, 1, 1, 0.07);
    cairo_pattern_add_color_stop_rgba(sheen, 1.0, 1, 1, 1, 0.0);
    cairo_set_source(cr, sheen);
    cairo_fill(cr);
    cairo_pattern_destroy(sheen);

    // ---- the carved wolf, centred on the blue rule ----
    const double wolf_h = H * 0.76;
    const double wolf_w = kWolfWidth;
    bm::draw_carved_wolf(cr, kBarWidth, (H - wolf_h) / 2.0, wolf_w, wolf_h, 1.0);

    // ---- the blue rule down the left edge ----
    cairo_pattern_t* bar = cairo_pattern_create_linear(0, 0, 0, H);
    cairo_pattern_add_color_stop_rgba(bar, 0.0, 0.290, 0.569, 0.949, 0.97);
    cairo_pattern_add_color_stop_rgba(bar, 1.0, 0.106, 0.341, 0.784, 0.97);
    cairo_rectangle(cr, 0, 0, kBarWidth, H);
    cairo_set_source(cr, bar);
    cairo_fill(cr);
    cairo_pattern_destroy(bar);

    // Highlight on the inner face of the rule, so it also reads as raised metal.
    cairo_rectangle(cr, kBarWidth - 1.0, 0, 1.0, H);
    cairo_set_source_rgba(cr, 1, 1, 1, 0.18);
    cairo_fill(cr);

    // ---- countdown for self-dismissing alerts ----
    if (self->style_.auto_close_ms > 0 && self->alert_.severity != Severity::Critical) {
        double elapsed = (g_get_monotonic_time() - self->opened_us_) / 1000.0;
        double left = 1.0 - elapsed / self->style_.auto_close_ms;
        if (left < 0) left = 0;
        Rgb c = severity_colour(self->alert_.severity);
        cairo_rectangle(cr, kBarWidth, H - 2.5, (W - kBarWidth) * left, 2.5);
        cairo_set_source_rgba(cr, c.r, c.g, c.b, 0.85);
        cairo_fill(cr);
    }

    cairo_restore(cr);

    // ---- hairline border ----
    rounded_rect(cr, 0.5, 0.5, W - 1, H - 1, kRadius);
    cairo_set_line_width(cr, 1.0);
    cairo_set_source_rgba(cr, 1, 1, 1, 0.16);
    cairo_stroke(cr);
}

GtkWidget* Popup::build_content() {
    GtkWidget* root = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_margin_start(root, static_cast<int>(kContentLeft));
    gtk_widget_set_margin_end(root, 22);
    gtk_widget_set_margin_top(root, 16);
    gtk_widget_set_margin_bottom(root, 18);

    // --- header: brand, severity chip, close button ---
    GtkWidget* header = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);

    GtkWidget* brand = gtk_label_new("BACKMASTER");
    gtk_widget_add_css_class(brand, "bm-brand");
    gtk_widget_set_halign(brand, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(header), brand);

    GtkWidget* chip = gtk_label_new(severity_label(alert_.severity));
    gtk_widget_add_css_class(chip, "bm-chip");
    gtk_widget_add_css_class(chip, to_string(alert_.severity));
    gtk_widget_set_valign(chip, GTK_ALIGN_CENTER);
    gtk_box_append(GTK_BOX(header), chip);

    GtkWidget* spacer = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_widget_set_hexpand(spacer, TRUE);
    gtk_box_append(GTK_BOX(header), spacer);

    GtkWidget* x = gtk_button_new_with_label("✕");
    gtk_widget_add_css_class(x, "bm-x");
    gtk_widget_set_valign(x, GTK_ALIGN_START);
    g_signal_connect(x, "clicked", G_CALLBACK(on_close_clicked), this);
    gtk_box_append(GTK_BOX(header), x);

    gtk_box_append(GTK_BOX(root), header);

    // --- title ---
    GtkWidget* title = gtk_label_new(nullptr);
    gtk_label_set_markup(GTK_LABEL(title),
                         ("<b>" + escape_markup(alert_.title) + "</b>").c_str());
    gtk_widget_add_css_class(title, "bm-title");
    gtk_label_set_wrap(GTK_LABEL(title), TRUE);
    gtk_label_set_xalign(GTK_LABEL(title), 0.0);
    gtk_widget_set_margin_top(title, 10);
    gtk_box_append(GTK_BOX(root), title);

    // --- detail ---
    if (!alert_.detail.empty()) {
        GtkWidget* detail = gtk_label_new(alert_.detail.c_str());
        gtk_widget_add_css_class(detail, "bm-detail");
        gtk_label_set_wrap(GTK_LABEL(detail), TRUE);
        gtk_label_set_xalign(GTK_LABEL(detail), 0.0);
        gtk_label_set_max_width_chars(GTK_LABEL(detail), 52);
        gtk_widget_set_margin_top(detail, 6);
        gtk_box_append(GTK_BOX(root), detail);
    }

    // --- the label / value table ---
    GtkWidget* grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 3);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 16);
    gtk_widget_set_margin_top(grid, 14);

    int row = 0;
    for (const auto& [k, v] : alert_.fields) {
        if (row >= 6) break; // the popup stays a summary; the log has the rest
        GtkWidget* key = gtk_label_new((k + " :").c_str());
        gtk_widget_add_css_class(key, "bm-key");
        gtk_label_set_xalign(GTK_LABEL(key), 0.0);
        gtk_grid_attach(GTK_GRID(grid), key, 0, row, 1, 1);

        GtkWidget* val = gtk_label_new(elide(v, 46).c_str());
        gtk_widget_add_css_class(val, "bm-value");
        gtk_label_set_xalign(GTK_LABEL(val), 0.0);
        gtk_label_set_selectable(GTK_LABEL(val), TRUE);
        gtk_widget_set_tooltip_text(val, v.c_str());
        gtk_grid_attach(GTK_GRID(grid), val, 1, row, 1, 1);
        ++row;
    }
    gtk_box_append(GTK_BOX(root), grid);

    GtkWidget* fill = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_vexpand(fill, TRUE);
    gtk_box_append(GTK_BOX(root), fill);

    // --- footer: status note and buttons ---
    GtkWidget* footer = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);

    note_label_ = gtk_label_new("");
    gtk_widget_add_css_class(note_label_, "bm-note");
    gtk_label_set_xalign(GTK_LABEL(note_label_), 0.0);
    gtk_label_set_wrap(GTK_LABEL(note_label_), TRUE);
    gtk_widget_set_hexpand(note_label_, TRUE);
    gtk_widget_set_valign(note_label_, GTK_ALIGN_CENTER);
    gtk_box_append(GTK_BOX(footer), note_label_);

    GtkWidget* close = gtk_button_new_with_label("Close");
    gtk_widget_add_css_class(close, "bm-secondary");
    g_signal_connect(close, "clicked", G_CALLBACK(on_close_clicked), this);
    gtk_box_append(GTK_BOX(footer), close);

    // Only an alert with something excludable gets the primary action.
    if (!alert_.subject.empty() &&
        (alert_.subject_kind == "ip" || alert_.subject_kind == "domain")) {
        exclude_button_ = gtk_button_new_with_label("Manage Exclusions");
        gtk_widget_add_css_class(exclude_button_, "bm-primary");
        g_signal_connect(exclude_button_, "clicked", G_CALLBACK(on_exclude_clicked), this);
        gtk_box_append(GTK_BOX(footer), exclude_button_);
    }

    gtk_box_append(GTK_BOX(root), footer);
    return root;
}

void Popup::build() {
    popup_install_css();

    window_ = gtk_application_window_new(app_);
    gtk_widget_add_css_class(window_, "backmaster");
    gtk_window_set_title(GTK_WINDOW(window_), "BackMaster");
    gtk_window_set_decorated(GTK_WINDOW(window_), FALSE);
    gtk_window_set_resizable(GTK_WINDOW(window_), FALSE);
    gtk_window_set_default_size(GTK_WINDOW(window_), style_.width, style_.height);

    area_ = gtk_drawing_area_new();
    gtk_drawing_area_set_draw_func(GTK_DRAWING_AREA(area_), on_draw, this, nullptr);
    gtk_widget_set_hexpand(area_, TRUE);
    gtk_widget_set_vexpand(area_, TRUE);

    GtkWidget* overlay = gtk_overlay_new();
    gtk_overlay_set_child(GTK_OVERLAY(overlay), area_);
    gtk_overlay_add_overlay(GTK_OVERLAY(overlay), build_content());
    gtk_window_set_child(GTK_WINDOW(window_), overlay);

    GtkEventController* keys = gtk_event_controller_key_new();
    g_signal_connect(keys, "key-pressed", G_CALLBACK(on_key), this);
    gtk_widget_add_controller(window_, keys);

    g_signal_connect(window_, "destroy", G_CALLBACK(on_destroy), this);

    opened_us_ = g_get_monotonic_time();
    gtk_widget_add_tick_callback(window_, on_tick, this, nullptr);

    gtk_window_present(GTK_WINDOW(window_));
}

void Popup::note(const std::string& text, bool error) {
    if (!note_label_) return;
    gtk_label_set_text(GTK_LABEL(note_label_), text.c_str());
    gtk_widget_remove_css_class(note_label_, error ? "ok" : "error");
    gtk_widget_add_css_class(note_label_, error ? "error" : "ok");
}

void Popup::dismiss() {
    if (closing_) return;
    closing_ = true;
    if (window_) gtk_window_destroy(GTK_WINDOW(window_));
}

void Popup::on_close_clicked(GtkButton*, gpointer data) {
    static_cast<Popup*>(data)->dismiss();
}

void Popup::on_exclude_clicked(GtkButton*, gpointer data) {
    auto* self = static_cast<Popup*>(data);
    if (self->on_exclude_) {
        self->on_exclude_(self->alert_);
        self->note("Requested exclusion for " + self->alert_.subject, false);
        if (self->exclude_button_) gtk_widget_set_sensitive(self->exclude_button_, FALSE);
        // Give the user a moment to read the confirmation before it disappears.
        self->style_.auto_close_ms = 0;
    }
}

gboolean Popup::on_key(GtkEventControllerKey*, guint keyval, guint, GdkModifierType,
                       gpointer data) {
    if (keyval == GDK_KEY_Escape) {
        static_cast<Popup*>(data)->dismiss();
        return TRUE;
    }
    return FALSE;
}

gboolean Popup::on_tick(GtkWidget*, GdkFrameClock*, gpointer data) {
    auto* self = static_cast<Popup*>(data);
    if (self->closing_) return G_SOURCE_REMOVE;
    if (self->style_.auto_close_ms > 0 && self->alert_.severity != Severity::Critical) {
        gint64 elapsed_ms = (g_get_monotonic_time() - self->opened_us_) / 1000;
        if (elapsed_ms >= self->style_.auto_close_ms) {
            self->dismiss();
            return G_SOURCE_REMOVE;
        }
        gtk_widget_queue_draw(self->area_);
    }
    return G_SOURCE_CONTINUE;
}

void Popup::on_destroy(GtkWidget*, gpointer data) {
    auto* self = static_cast<Popup*>(data);
    self->closing_ = true;
    self->window_ = nullptr;
    ClosedFn cb = std::move(self->on_closed_);
    delete self;
    if (cb) cb();
}

} // namespace bm
