#pragma once

#include <functional>
#include <string>

#include <gtk/gtk.h>

#include "bm/alert.hpp"

namespace bm {

struct PopupStyle {
    // 1.0 is fully opaque. The panel is a neutral grey at this alpha.
    double opacity = 0.70;
    int width = 640;
    int height = 340;
    // Alerts below Critical dismiss themselves after this long. 0 disables.
    int auto_close_ms = 15000;
    bool corner_anchor = true;
};

// One popup window, owned by GTK. It destroys itself when dismissed and calls
// `on_closed` afterwards so the agent can show the next queued alert.
class Popup {
public:
    using ExcludeFn = std::function<void(const Alert&)>;
    using ClosedFn = std::function<void()>;

    static void present(GtkApplication* app, const Alert& alert, const PopupStyle& style,
                        ExcludeFn on_exclude, ClosedFn on_closed);

private:
    Popup(GtkApplication* app, const Alert& alert, const PopupStyle& style,
          ExcludeFn on_exclude, ClosedFn on_closed);

    void build();
    GtkWidget* build_content();
    void dismiss();
    void note(const std::string& text, bool error);

    static void on_draw(GtkDrawingArea* area, cairo_t* cr, int w, int h, gpointer data);
    static void on_close_clicked(GtkButton* b, gpointer data);
    static void on_exclude_clicked(GtkButton* b, gpointer data);
    static gboolean on_tick(GtkWidget* w, GdkFrameClock* clock, gpointer data);
    static gboolean on_key(GtkEventControllerKey* c, guint keyval, guint keycode,
                           GdkModifierType state, gpointer data);
    static void on_destroy(GtkWidget* w, gpointer data);

    Alert alert_;
    PopupStyle style_;
    ExcludeFn on_exclude_;
    ClosedFn on_closed_;

    GtkApplication* app_ = nullptr;
    GtkWidget* window_ = nullptr;
    GtkWidget* area_ = nullptr;
    GtkWidget* note_label_ = nullptr;
    GtkWidget* exclude_button_ = nullptr;

    gint64 opened_us_ = 0;
    bool closing_ = false;
};

// Loads the shared stylesheet once per process.
void popup_install_css();

} // namespace bm
