//! Hand-rolled widgets that give the app its "printed paper" look.
//!
//! egui's stock widgets are perfectly usable but they carry a rounded, glossy
//! feel that fights the paper aesthetic and they cannot place a vector icon
//! next to a label inside the button body. Everything here is therefore painted
//! directly, which also keeps layout tight and allocation-free on the hot path.

use eframe::egui;
use egui::{
    Align, Color32, CornerRadius, Layout, Margin, Pos2, Rect, Response, RichText, Sense,
    StrokeKind, Ui, Vec2,
};

use crate::icons::{self, Icon};
use crate::theme::{self, Palette, Tone};

/// Content wider than this is centred instead of stretched edge to edge.
pub const MAX_CONTENT_W: f32 = 1120.0;

// ---------------------------------------------------------------------------
// Layout scaffolding
// ---------------------------------------------------------------------------

/// Constrain and centre page content, then run `add`.
///
/// Content is capped at [`MAX_CONTENT_W`] so text keeps a readable line length
/// on a wide monitor instead of stretching the full width of the window.
pub fn page(ui: &mut Ui, add: impl FnOnce(&mut Ui)) {
    let avail = ui.available_width();
    let content_w = avail.min(MAX_CONTENT_W);
    let pad = ((avail - content_w) * 0.5).max(0.0);

    ui.horizontal_top(|ui| {
        if pad > 0.5 {
            ui.add_space(pad);
        }
        ui.vertical(|ui| {
            ui.set_width(content_w);
            add(ui);
        });
    });
}

/// Right-align content inside the current row, within a bounded region.
///
/// `ui.with_layout(Layout::right_to_left(Align::Center), …)` looks like the
/// obvious way to push a button to the right edge, and it is fine in a row that
/// centres its children. But when the row is **top**-aligned (`horizontal_top`)
/// the row's available height is the parent's, which inside a `ScrollArea` is
/// unbounded, and egui then centres the child against that unbounded height.
/// Measured in this app that stretched a one-line row to 372 px and the page
/// header to 409 px, which is why every page had to be scrolled.
///
/// Bounding the region to a single control height gives egui a finite rectangle
/// to centre in. Content taller than that still grows the region, it just is not
/// measured against infinity any more.
pub fn right_aligned<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> R {
    let width = ui.available_width();
    ui.allocate_ui_with_layout(
        Vec2::new(width, theme::CONTROL_H),
        Layout::right_to_left(Align::Center),
        add,
    )
    .inner
}

/// Page heading with an icon, a title, a subtitle and right-aligned actions.
pub fn page_header(
    ui: &mut Ui,
    icon: Icon,
    title: &str,
    subtitle: &str,
    actions: impl FnOnce(&mut Ui),
) {
    let pal = Palette::current(ui);
    // `ui.horizontal` centres its children vertically; `horizontal_top` does not,
    // which is what used to blow this header up to 409 px (see `right_aligned`).
    ui.horizontal(|ui| {
        let (icon_rect, _) = ui.allocate_exact_size(Vec2::splat(32.0), Sense::hover());
        icons::draw(ui.painter(), icon_rect, icon, pal.accent, 32.0);

        ui.add_space(3.0);
        ui.vertical(|ui| {
            ui.add_space(1.0);
            ui.label(theme::title(title).color(pal.ink));
            if !subtitle.is_empty() {
                ui.add_space(1.0);
                ui.label(theme::small(subtitle).color(pal.ink_soft));
            }
        });

        right_aligned(ui, |ui| actions(ui));
    });

    ui.add_space(6.0);
    theme::accent_rule(ui);
    ui.add_space(11.0);
}

/// A raised card that fills the available width.
pub fn card<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> R {
    card_tuned(ui, None, None, None, add)
}

/// A card with explicit surface / border / padding.
pub fn card_tuned<R>(
    ui: &mut Ui,
    fill: Option<Color32>,
    stroke: Option<Color32>,
    padding: Option<f32>,
    add: impl FnOnce(&mut Ui) -> R,
) -> R {
    let pal = Palette::current(ui);
    egui::Frame::new()
        .fill(fill.unwrap_or(pal.card))
        .stroke(theme::hairline(stroke.unwrap_or(pal.rule)))
        .corner_radius(theme::radius(theme::R_LG))
        .inner_margin(Margin::same(padding.unwrap_or(16.0).round() as i8))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            add(ui)
        })
        .inner
}

/// A tinted card, used for status banners and threat rows.
pub fn tone_card<R>(ui: &mut Ui, tone: Tone, add: impl FnOnce(&mut Ui) -> R) -> R {
    let pal = Palette::current(ui);
    card_tuned(
        ui,
        Some(pal.surface(tone)),
        Some(pal.tone_ink(tone).gamma_multiply(0.28)),
        None,
        add,
    )
}

/// A recessed well, used for logs.
pub fn well<R>(ui: &mut Ui, max_height: f32, add: impl FnOnce(&mut Ui) -> R) -> R {
    well_sized(ui, 0.0, max_height, add)
}

/// Vertical padding [`well_sized`] adds around its content (10 top + 10 bottom).
pub const WELL_PAD_Y: f32 = 20.0;

/// A recessed well whose content is forced to `min_height` and capped at
/// `max_height`.
///
/// The minimum matters as much as the maximum: with only a cap, a two line log
/// shrank to two lines and left the rest of the page as bare paper.
pub fn well_sized<R>(
    ui: &mut Ui,
    min_height: f32,
    max_height: f32,
    add: impl FnOnce(&mut Ui) -> R,
) -> R {
    let pal = Palette::current(ui);
    egui::Frame::new()
        .fill(pal.sunken)
        .stroke(theme::hairline(pal.rule))
        .corner_radius(theme::radius(theme::R_MD))
        .inner_margin(Margin::symmetric(12, 10))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.set_min_height(min_height);
            ui.set_max_height(max_height);
            add(ui)
        })
        .inner
}

/// How much vertical room is left on the page for a flexible element.
///
/// `page_height` is the height the page may occupy, measured by the caller
/// *outside* the page's scroll area. Deliberately not `ui.available_height()`:
/// inside a scroll area that value depends on the size the content had on the
/// previous frame, so a list that sizes itself from it oscillates — measured in
/// this app that made one page overflow while another stayed half empty. With a
/// height fixed outside, the arithmetic below is plain and stable.
///
/// `ui` supplies how much of the page is already used, `reserve` keeps room for
/// padding and a little air, and `min` stops a short window from squashing the
/// element to nothing — such a page simply scrolls instead.
pub fn fill_height(ui: &Ui, page_height: f32, reserve: f32, min: f32) -> f32 {
    budget(page_height, ui.min_rect().height(), reserve, min)
}

/// Height for a well that is the last element inside a card.
///
/// Get `card_budget` from [`fill_height`] at page level, then call this *inside*
/// the card closure: `ui` is then the card's own layout, so
/// `ui.min_rect().height()` is exactly what the card has used so far, and no
/// caller has to guess how tall the heading above the well turned out to be.
/// `pad_total` is the card's whole vertical padding (top *and* bottom), which is
/// what makes the finished card come out at exactly `card_budget`.
pub fn well_in_card(ui: &Ui, card_budget: f32, pad_total: f32, min: f32) -> f32 {
    budget(card_budget, ui.min_rect().height(), pad_total, min)
}

/// What is left of `total` once `used` and `reserve` are accounted for.
///
/// Clamped to `min` so callers are never handed a negative or zero size: a
/// negative allocation panics, and a collapsed one looks like a rendering bug.
/// Clamping means a window too short for the page scrolls, which is the
/// behaviour we want anyway.
fn budget(total: f32, used: f32, reserve: f32, min: f32) -> f32 {
    (total - used - reserve).max(min)
}

/// A section heading followed by a hairline rule.
///
/// Drawn above a group of rows inside a card. Returning the header as its own
/// call (rather than wrapping the body in a closure) keeps long forms readable
/// and avoids one more level of indentation.
pub fn section(ui: &mut Ui, title: &str) {
    let pal = Palette::current(ui);
    ui.label(theme::section_title(title).color(pal.ink));
    ui.add_space(4.0);
    theme::rule(ui);
    ui.add_space(8.0);
}

/// Inline hint text.
pub fn hint(ui: &mut Ui, text: &str) {
    let pal = Palette::current(ui);
    ui.label(theme::small(text).color(pal.ink_faint));
}

/// Label + value pair on one line.
pub fn kv(ui: &mut Ui, key: &str, value: &str, value_color: Option<Color32>) {
    let pal = Palette::current(ui);
    ui.horizontal(|ui| {
        ui.label(theme::small(key).color(pal.ink_faint));
        ui.label(
            theme::body(value)
                .color(value_color.unwrap_or(pal.ink))
                .strong(),
        );
    });
}

// ---------------------------------------------------------------------------
// Buttons
// ---------------------------------------------------------------------------

/// Visual weight of a button.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Btn {
    /// Solid accent fill – the one primary action of a page.
    Primary,
    /// Paper fill with a hairline border – secondary actions.
    Outline,
    /// No chrome at all – inline / tertiary actions.
    Quiet,
    /// Solid danger fill – destructive and confirmable.
    Danger,
    /// Danger-tinted outline – destructive but reversible.
    DangerOutline,
}

fn button_colors(
    pal: &Palette,
    kind: Btn,
    enabled: bool,
    hovered: bool,
    pressed: bool,
) -> (Option<Color32>, Option<Color32>, Color32) {
    if !enabled {
        return match kind {
            Btn::Primary => (Some(pal.accent_soft), None, pal.ink_faint),
            Btn::Danger => (Some(pal.danger_surface), None, pal.ink_faint),
            Btn::DangerOutline => (Some(pal.card), Some(pal.rule), pal.ink_faint),
            _ => (Some(pal.card_alt), Some(pal.rule), pal.ink_faint),
        };
    }

    match kind {
        Btn::Primary => {
            let fill = if pressed {
                pal.accent_strong
            } else if hovered {
                pal.accent_strong
            } else {
                pal.accent
            };
            (Some(fill), None, pal.on_accent)
        }
        Btn::Outline => {
            let fill = if pressed || hovered {
                pal.card_hover
            } else {
                pal.card
            };
            let stroke = if hovered { pal.accent } else { pal.rule_strong };
            (Some(fill), Some(stroke), pal.ink)
        }
        Btn::Quiet => {
            let fill = if pressed {
                Some(pal.accent_soft)
            } else if hovered {
                Some(pal.card_hover)
            } else {
                None
            };
            (fill, None, if hovered { pal.ink } else { pal.ink_soft })
        }
        Btn::Danger => {
            let fill = if hovered || pressed {
                pal.danger.gamma_multiply(0.85)
            } else {
                pal.danger
            };
            (Some(fill), None, pal.on_accent)
        }
        Btn::DangerOutline => {
            let fill = if pressed || hovered {
                pal.danger_surface
            } else {
                pal.card
            };
            (Some(fill), Some(pal.danger.gamma_multiply(0.55)), pal.danger)
        }
    }
}

/// The generic button. Prefer the `primary`/`outline`/`quiet` shorthands.
pub fn button(
    ui: &mut Ui,
    kind: Btn,
    icon: Option<Icon>,
    label: &str,
    enabled: bool,
    min_width: f32,
) -> Response {
    let pal = Palette::current(ui);

    let icon_size = 16.0;
    let gap = if icon.is_some() && !label.is_empty() {
        7.0
    } else {
        0.0
    };
    let icon_w = if icon.is_some() { icon_size } else { 0.0 };
    let pad_x = if kind == Btn::Quiet { 9.0 } else { 14.0 };

    let galley = ui
        .painter()
        .layout_no_wrap(label.to_owned(), theme::font(13.5), Color32::PLACEHOLDER);

    let width = (galley.size().x + icon_w + gap + pad_x * 2.0).max(min_width);
    let height = theme::CONTROL_H;

    let sense = if enabled { Sense::click() } else { Sense::hover() };
    let (rect, response) = ui.allocate_exact_size(Vec2::new(width, height), sense);

    if !ui.is_rect_visible(rect) {
        return response;
    }

    let hovered = enabled && response.hovered();
    let pressed = enabled && response.is_pointer_button_down_on();
    let (fill, stroke, fg) = button_colors(&pal, kind, enabled, hovered, pressed);

    let radius = theme::radius(theme::R_MD);
    let painter = ui.painter();
    if let Some(fill) = fill {
        painter.rect_filled(rect, radius, fill);
    }
    if let Some(stroke) = stroke {
        painter.rect_stroke(rect, radius, theme::hairline(stroke), StrokeKind::Inside);
    }
    if enabled && response.has_focus() {
        painter.rect_stroke(
            rect.expand(1.5),
            radius,
            theme::hairline(pal.accent.gamma_multiply(0.6)),
            StrokeKind::Outside,
        );
    }

    let mut x = rect.min.x + pad_x;
    let cy = rect.center().y;

    if let Some(icon) = icon {
        let ir = Rect::from_min_size(Pos2::new(x, cy - icon_size / 2.0), Vec2::splat(icon_size));
        icons::draw(painter, ir, icon, fg, icon_size);
        x += icon_size + gap;
    }

    painter.galley(
        Pos2::new(x, cy - galley.size().y / 2.0),
        galley,
        if enabled { fg } else { pal.ink_faint },
    );

    if enabled {
        response.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        response
    }
}

/// Solid accent button – the primary action.
pub fn primary(ui: &mut Ui, icon: Option<Icon>, label: &str) -> Response {
    button(ui, Btn::Primary, icon, label, true, 0.0)
}

/// Solid accent button with an enabled flag.
pub fn primary_enabled(ui: &mut Ui, icon: Option<Icon>, label: &str, enabled: bool) -> Response {
    button(ui, Btn::Primary, icon, label, enabled, 0.0)
}

/// Paper button with a hairline border.
pub fn outline(ui: &mut Ui, icon: Option<Icon>, label: &str) -> Response {
    button(ui, Btn::Outline, icon, label, true, 0.0)
}

/// Paper button with a hairline border and an enabled flag.
pub fn outline_enabled(ui: &mut Ui, icon: Option<Icon>, label: &str, enabled: bool) -> Response {
    button(ui, Btn::Outline, icon, label, enabled, 0.0)
}

/// Chrome-less inline action.
pub fn quiet(ui: &mut Ui, icon: Option<Icon>, label: &str) -> Response {
    button(ui, Btn::Quiet, icon, label, true, 0.0)
}

/// Chrome-less inline action with an enabled flag.
pub fn quiet_enabled(ui: &mut Ui, icon: Option<Icon>, label: &str, enabled: bool) -> Response {
    button(ui, Btn::Quiet, icon, label, enabled, 0.0)
}

/// Solid destructive button.
pub fn danger(ui: &mut Ui, icon: Option<Icon>, label: &str) -> Response {
    button(ui, Btn::Danger, icon, label, true, 0.0)
}

/// Outlined destructive button.
pub fn danger_outline(ui: &mut Ui, icon: Option<Icon>, label: &str) -> Response {
    button(ui, Btn::DangerOutline, icon, label, true, 0.0)
}

/// Outlined destructive button with an enabled flag.
pub fn danger_outline_enabled(
    ui: &mut Ui,
    icon: Option<Icon>,
    label: &str,
    enabled: bool,
) -> Response {
    button(ui, Btn::DangerOutline, icon, label, enabled, 0.0)
}

/// A large, full-width action row: icon in a tinted square, a title, a hint and
/// a chevron. Used for the "quick scan" choices, where a plain button is too
/// small a target for what is really a navigation choice.
pub fn quick_action(ui: &mut Ui, icon: Icon, title: &str, hint_text: &str) -> Response {
    let pal = Palette::current(ui);
    let height = if hint_text.is_empty() { 42.0 } else { 52.0 };
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), height), Sense::click());

    if !ui.is_rect_visible(rect) {
        return response;
    }

    let hovered = response.hovered();
    let radius = theme::radius(theme::R_MD);
    let painter = ui.painter();

    painter.rect_filled(
        rect,
        radius,
        if hovered { pal.card_hover } else { pal.card_alt },
    );
    painter.rect_stroke(
        rect,
        radius,
        theme::hairline(if hovered { pal.rule_strong } else { pal.rule }),
        StrokeKind::Inside,
    );

    // Tinted icon plate.
    let plate = Rect::from_min_size(
        egui::pos2(rect.min.x + 11.0, rect.center().y - 15.0),
        Vec2::splat(30.0),
    );
    painter.rect_filled(plate, theme::radius(theme::R_SM), pal.accent_soft);
    icons::draw(painter, plate.shrink(7.0), icon, pal.accent, 16.0);

    let text_x = plate.max.x + 12.0;

    let title_galley = painter.layout_no_wrap(
        title.to_owned(),
        theme::font(theme::FS_BODY),
        Color32::PLACEHOLDER,
    );
    let hint_galley = if hint_text.is_empty() {
        None
    } else {
        Some(painter.layout_no_wrap(
            hint_text.to_owned(),
            theme::font(theme::FS_SMALL),
            Color32::PLACEHOLDER,
        ))
    };

    // Vertically centre the text block.
    let title_h = title_galley.size().y;
    let hint_h = hint_galley
        .as_ref()
        .map(|g| g.size().y + 2.0)
        .unwrap_or(0.0);
    let mut y = rect.center().y - (title_h + hint_h) / 2.0;

    painter.galley(egui::pos2(text_x, y), title_galley, pal.ink);
    y += title_h + 2.0;

    if let Some(hint_galley) = hint_galley {
        painter.galley(egui::pos2(text_x, y), hint_galley, pal.ink_faint);
    }

    let chevron = Rect::from_min_size(
        egui::pos2(rect.max.x - 24.0, rect.center().y - 7.0),
        Vec2::splat(14.0),
    );
    icons::draw(
        painter,
        chevron,
        Icon::ChevronRight,
        if hovered { pal.accent } else { pal.ink_faint },
        14.0,
    );

    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// Icon-only square button.
pub fn icon_button(ui: &mut Ui, icon: Icon, tooltip: &str) -> Response {
    let pal = Palette::current(ui);
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(30.0), Sense::click());
    if ui.is_rect_visible(rect) {
        let hovered = response.hovered();
        let radius = theme::radius(theme::R_SM);
        if hovered {
            ui.painter().rect_filled(rect, radius, pal.card_hover);
        }
        let fg = if hovered { pal.ink } else { pal.ink_soft };
        icons::draw(ui.painter(), rect.shrink(7.0), icon, fg, 16.0);
    }
    response
        .on_hover_text(tooltip)
        .on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// A selectable pill, used for scan presets and rule types.
pub fn choice_chip(ui: &mut Ui, selected: bool, icon: Option<Icon>, label: &str) -> Response {
    let pal = Palette::current(ui);

    let icon_size = 15.0;
    let gap = if icon.is_some() { 6.0 } else { 0.0 };
    let icon_w = if icon.is_some() { icon_size } else { 0.0 };
    let galley = ui.painter().layout_no_wrap(
        label.to_owned(),
        theme::font(13.0),
        Color32::PLACEHOLDER,
    );
    let width = galley.size().x + icon_w + gap + 26.0;
    let (rect, response) = ui.allocate_exact_size(Vec2::new(width, 30.0), Sense::click());

    if ui.is_rect_visible(rect) {
        let hovered = response.hovered();
        let radius = CornerRadius::same(15);
        let (fill, stroke_col, fg) = if selected {
            (pal.accent_soft, pal.accent, pal.accent)
        } else if hovered {
            (pal.card_hover, pal.rule_strong, pal.ink)
        } else {
            (pal.card, pal.rule, pal.ink_soft)
        };

        let painter = ui.painter();
        painter.rect_filled(rect, radius, fill);
        painter.rect_stroke(rect, radius, theme::hairline(stroke_col), StrokeKind::Inside);

        let mut x = rect.min.x + 13.0;
        let cy = rect.center().y;
        if let Some(icon) = icon {
            let ir = Rect::from_min_size(Pos2::new(x, cy - icon_size / 2.0), Vec2::splat(icon_size));
            icons::draw(painter, ir, icon, fg, icon_size);
            x += icon_size + gap;
        }
        painter.galley(Pos2::new(x, cy - galley.size().y / 2.0), galley, fg);
    }

    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

// ---------------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------------

/// A full-width navigation entry for the rail.
pub fn nav_item(
    ui: &mut Ui,
    icon: Icon,
    label: &str,
    selected: bool,
    badge: Option<String>,
) -> Response {
    let pal = Palette::current(ui);
    let width = ui.available_width();
    let (rect, response) = ui.allocate_exact_size(Vec2::new(width, 40.0), Sense::click());

    if ui.is_rect_visible(rect) {
        let hovered = response.hovered();
        let radius = theme::radius(theme::R_MD);
        let painter = ui.painter();

        if selected {
            painter.rect_filled(rect, radius, pal.accent_soft);
            let bar = Rect::from_min_size(
                Pos2::new(rect.min.x, rect.center().y - 9.0),
                Vec2::new(3.0, 18.0),
            );
            painter.rect_filled(bar, CornerRadius::same(2), pal.accent);
        } else if hovered {
            painter.rect_filled(rect, radius, pal.card_hover);
        }

        let fg = if selected {
            pal.accent
        } else if hovered {
            pal.ink
        } else {
            pal.ink_soft
        };

        let icon_size = 18.0;
        let ir = Rect::from_min_size(
            Pos2::new(rect.min.x + 14.0, rect.center().y - icon_size / 2.0),
            Vec2::splat(icon_size),
        );
        icons::draw(painter, ir, icon, fg, icon_size);

        let galley = painter.layout_no_wrap(
            label.to_owned(),
            theme::font(13.5),
            Color32::PLACEHOLDER,
        );
        painter.galley(
            Pos2::new(
                rect.min.x + 43.0,
                rect.center().y - galley.size().y / 2.0,
            ),
            galley,
            fg,
        );

        if let Some(badge) = badge {
            let galley =
                painter.layout_no_wrap(badge, theme::font(11.0), Color32::PLACEHOLDER);
            let w = galley.size().x + 14.0;
            let brect = Rect::from_min_size(
                Pos2::new(rect.max.x - 12.0 - w, rect.center().y - 9.0),
                Vec2::new(w, 18.0),
            );
            painter.rect_filled(brect, CornerRadius::same(9), pal.danger);
            painter.galley(
                Pos2::new(brect.min.x + 7.0, brect.center().y - galley.size().y / 2.0),
                galley,
                pal.on_accent,
            );
        }
    }

    response
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .on_hover_text(label)
}

// ---------------------------------------------------------------------------
// Status primitives
// ---------------------------------------------------------------------------

/// A small rounded badge.
pub fn pill(ui: &mut Ui, icon: Option<Icon>, text: &str, tone: Tone) {
    let pal = Palette::current(ui);
    let icon_size = 13.0;
    let gap = if icon.is_some() { 5.0 } else { 0.0 };
    let galley = ui.painter().layout_no_wrap(
        text.to_owned(),
        theme::font(11.5),
        Color32::PLACEHOLDER,
    );
    let width = galley.size().x + if icon.is_some() { icon_size + gap } else { 0.0 } + 20.0;
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, 22.0), Sense::hover());

    if ui.is_rect_visible(rect) {
        let fg = pal.tone_ink(tone);
        let painter = ui.painter();
        painter.rect_filled(rect, CornerRadius::same(11), pal.surface(tone));
        painter.rect_stroke(
            rect,
            CornerRadius::same(11),
            theme::hairline(fg.gamma_multiply(0.25)),
            StrokeKind::Inside,
        );

        let mut x = rect.min.x + 10.0;
        let cy = rect.center().y;
        if let Some(icon) = icon {
            let ir = Rect::from_min_size(Pos2::new(x, cy - icon_size / 2.0), Vec2::splat(icon_size));
            icons::draw(painter, ir, icon, fg, icon_size);
            x += icon_size + gap;
        }
        painter.galley(Pos2::new(x, cy - galley.size().y / 2.0), galley, fg);
    }
}

/// A big number with a caption and an icon chip.
pub fn stat_tile(ui: &mut Ui, icon: Icon, value: &str, label: &str, tone: Tone) {
    let pal = Palette::current(ui);
    card(ui, |ui| {
        ui.horizontal(|ui| {
            let (chip, _) = ui.allocate_exact_size(Vec2::splat(40.0), Sense::hover());
            ui.painter()
                .rect_filled(chip, theme::radius(theme::R_MD), pal.surface(tone));
            icons::draw(
                ui.painter(),
                chip.shrink(11.0),
                icon,
                pal.tone_ink(tone),
                18.0,
            );

            ui.add_space(11.0);
            ui.vertical(|ui| {
                ui.add_space(1.0);
                ui.label(
                    RichText::new(value)
                        .font(theme::font(theme::FS_NUMERIC))
                        .strong()
                        .color(pal.ink),
                );
                ui.label(theme::small(label).color(pal.ink_soft));
            });
        });
    });
}

/// Centred placeholder for an empty list.
pub fn empty_state(ui: &mut Ui, icon: Icon, title: &str, hint_text: &str, tone: Tone) {
    let pal = Palette::current(ui);
    card_tuned(
        ui,
        Some(pal.surface(tone)),
        Some(pal.tone_ink(tone).gamma_multiply(0.25)),
        Some(26.0),
        |ui| {
            ui.vertical_centered(|ui| {
                icons::paint(ui, icon, 38.0, pal.tone_ink(tone));
                ui.add_space(9.0);
                ui.label(
                    RichText::new(title)
                        .font(theme::font(14.5))
                        .strong()
                        .color(pal.tone_ink(tone)),
                );
                if !hint_text.is_empty() {
                    ui.add_space(3.0);
                    ui.label(theme::small(hint_text).color(pal.ink_soft));
                }
            });
        },
    );
}

/// Height [`empty_state`] occupies as laid out, so it can be centred in a page.
pub const EMPTY_STATE_H: f32 = 149.0;

/// An empty-state placeholder centred inside a card that fills the rest of the
/// page.
///
/// Left bare, the placeholder stranded a few hundred pixels of paper above and
/// below it, which reads as a half-finished page rather than as "there is
/// nothing here yet". The card gives the message a surface to sit on and makes
/// the page reach the bottom of the window exactly.
pub fn empty_state_filling(
    ui: &mut Ui,
    page_height: f32,
    icon: Icon,
    title: &str,
    hint_text: &str,
    tone: Tone,
) {
    const PAD: f32 = 16.0;
    let card_budget = fill_height(ui, page_height, 4.0, EMPTY_STATE_H + PAD * 2.0);
    let inner = (card_budget - PAD * 2.0).max(EMPTY_STATE_H);

    card_tuned(ui, None, None, Some(PAD), |ui| {
        // `set_min_height` grows the card but leaves the cursor at the top, so
        // the placeholder is centred by hand: half of the leftover room above
        // it, half below.
        ui.set_min_height(inner);
        ui.add_space(((inner - EMPTY_STATE_H) * 0.5).max(0.0));
        empty_state(ui, icon, title, hint_text, tone);
    });
}

/// A determinate (`fraction >= 0`) or indeterminate progress bar.
pub fn progress(ui: &mut Ui, fraction: f32, phase: f32, color: Color32, height: f32) {
    let pal = Palette::current(ui);
    let (rect, _) = ui.allocate_exact_size(
        Vec2::new(ui.available_width(), height),
        Sense::hover(),
    );
    if !ui.is_rect_visible(rect) {
        return;
    }

    let radius = CornerRadius::same((height / 2.0).round() as u8);
    let painter = ui.painter();
    painter.rect_filled(rect, radius, pal.rule);

    let track = rect.shrink(1.5);
    if fraction >= 0.0 {
        let w = (track.width() * fraction.clamp(0.0, 1.0)).max(0.0);
        if w > 0.5 {
            let bar = Rect::from_min_size(track.min, Vec2::new(w, track.height()));
            painter.rect_filled(bar, radius, color);
        }
    } else {
        // Sweeping segment for work whose total size is unknown.
        let span = 0.32f32;
        let t = (phase % 1.0) * (1.0 + span) - span;
        let x0 = track.min.x + track.width() * t.clamp(0.0, 1.0);
        let mut x1 = x0 + track.width() * span;
        if x0 < track.min.x {
            x1 -= track.min.x - x0;
        }
        let x0 = x0.max(track.min.x);
        let x1 = x1.min(track.max.x);
        if x1 > x0 {
            let bar = Rect::from_min_max(
                Pos2::new(x0, track.min.y),
                Pos2::new(x1, track.max.y),
            );
            painter.rect_filled(bar, radius, color);
        }
    }
}

// ---------------------------------------------------------------------------
// Toggles
// ---------------------------------------------------------------------------

/// A standalone animated switch.
pub fn switch(ui: &mut Ui, on: &mut bool) -> Response {
    let pal = Palette::current(ui);
    let (rect, mut response) = ui.allocate_exact_size(Vec2::new(40.0, 22.0), Sense::click());

    if response.clicked() {
        *on = !*on;
        response.mark_changed();
    }

    if ui.is_rect_visible(rect) {
        let t = ui
            .ctx()
            .animate_bool_with_time(ui.make_persistent_id(("switch", rect.min.y as i32)), *on, 0.12);
        let track = if *on { pal.accent } else { pal.rule_strong };
        let radius = CornerRadius::same(11);
        let painter = ui.painter();
        painter.rect_filled(rect, radius, track);
        let knob_x = egui::lerp((rect.min.x + 11.0)..=(rect.max.x - 11.0), t);
        painter.circle_filled(Pos2::new(knob_x, rect.center().y), 8.0, pal.card);
        painter.circle_stroke(
            Pos2::new(knob_x, rect.center().y),
            8.0,
            theme::hairline(pal.rule_strong),
        );
    }

    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// A settings row: title (+ optional hint) on the left, switch on the right.
///
/// The whole row is clickable, which is what people expect from a modern
/// settings screen.
pub fn toggle_row(ui: &mut Ui, on: &mut bool, title: &str, hint_text: &str) -> Response {
    let pal = Palette::current(ui);
    let height = if hint_text.is_empty() { 36.0 } else { 46.0 };
    let (rect, mut response) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), height), Sense::click());

    if response.clicked() {
        *on = !*on;
        response.mark_changed();
    }

    if ui.is_rect_visible(rect) {
        let hovered = response.hovered();
        let radius = theme::radius(theme::R_MD);
        let painter = ui.painter();

        if hovered {
            painter.rect_filled(rect, radius, pal.card_hover);
        }

        let switch_w = 40.0;
        let text_w = (rect.width() - switch_w - 30.0).max(40.0);
        let text_x = rect.min.x + 11.0;

        let title_galley = painter.layout(
            title.to_owned(),
            theme::font(13.5),
            if *on { pal.ink } else { pal.ink_soft },
            text_w,
        );
        let title_h = title_galley.size().y;
        let hint_h = if hint_text.is_empty() {
            0.0
        } else {
            15.0
        };
        let block_h = title_h + hint_h;
        let top = rect.center().y - block_h / 2.0;

        painter.galley(Pos2::new(text_x, top), title_galley, pal.ink);

        if !hint_text.is_empty() {
            let hint_galley = painter.layout(
                hint_text.to_owned(),
                theme::font(theme::FS_SMALL),
                pal.ink_faint,
                text_w,
            );
            painter.galley(
                Pos2::new(text_x, top + title_h + 1.0),
                hint_galley,
                pal.ink_faint,
            );
        }

        // Switch track.
        let track = Rect::from_min_size(
            Pos2::new(rect.max.x - 11.0 - switch_w, rect.center().y - 11.0),
            Vec2::new(switch_w, 22.0),
        );
        let t = ui.ctx().animate_bool_with_time(
            ui.make_persistent_id(("toggle_row", title)),
            *on,
            0.12,
        );
        painter.rect_filled(track, CornerRadius::same(11), if *on { pal.accent } else { pal.rule_strong });
        let knob_x = egui::lerp((track.min.x + 11.0)..=(track.max.x - 11.0), t);
        painter.circle_filled(Pos2::new(knob_x, track.center().y), 8.0, pal.card);
        painter.circle_stroke(
            Pos2::new(knob_x, track.center().y),
            8.0,
            theme::hairline(pal.rule_strong),
        );
    }

    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// A 19x19 checkbox with a tick, for list selection.
pub fn check_box(ui: &mut Ui, checked: &mut bool) -> Response {
    let pal = Palette::current(ui);
    let (rect, mut response) = ui.allocate_exact_size(Vec2::splat(19.0), Sense::click());

    if response.clicked() {
        *checked = !*checked;
        response.mark_changed();
    }

    if ui.is_rect_visible(rect) {
        let t = ui.ctx().animate_bool_with_time(
            ui.make_persistent_id(("check", rect.min.x as i32, rect.min.y as i32)),
            *checked,
            0.10,
        );
        let radius = theme::radius(theme::R_SM - 2);
        let painter = ui.painter();
        let fill = if *checked {
            pal.accent
        } else if response.hovered() {
            pal.card_hover
        } else {
            pal.card
        };
        painter.rect_filled(rect, radius, fill);
        painter.rect_stroke(
            rect,
            radius,
            theme::hairline(if *checked {
                pal.accent
            } else {
                pal.rule_strong
            }),
            StrokeKind::Inside,
        );
        if t > 0.05 {
            let inner = rect.shrink(3.0);
            icons::draw(
                painter,
                inner,
                Icon::Check,
                pal.on_accent.gamma_multiply(t),
                13.0,
            );
        }
    }

    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

// ---------------------------------------------------------------------------
// Log well
// ---------------------------------------------------------------------------

/// How a log line should be coloured.
pub type LineColor = fn(&str, &Palette) -> Color32;

/// Default colouring for scanner / updater output.
pub fn default_line_color(line: &str, pal: &Palette) -> Color32 {
    if line.contains("ERROR") || line.contains("错误") {
        pal.danger
    } else if line.contains("THREAT") || line.contains("FOUND") || line.contains("DETECTED") {
        pal.warning
    } else if line.contains("INFO") {
        pal.ink_soft
    } else {
        pal.ink_soft
    }
}

/// A virtualised, auto-scrolling monospace log view occupying exactly `height`.
///
/// Only the visible rows are laid out, so a ten-thousand line scan log costs
/// about the same as a ten line one. The height is exact rather than a maximum:
/// these wells are the element that takes up the slack on their page, and a
/// maximum let a short log leave the page looking half finished.
pub fn log_well(
    ui: &mut Ui,
    id: &str,
    lines: &[String],
    height: f32,
    colorize: LineColor,
) {
    let pal = Palette::current(ui);
    let height = height.max(48.0);
    let content_h = (height - WELL_PAD_Y).max(24.0);

    if lines.is_empty() {
        well_sized(ui, content_h, content_h, |ui| {
            ui.label(theme::mono_text("—").color(pal.ink_faint));
        });
        return;
    }

    // Show only the tail of very long logs.
    const MAX_ROWS: usize = 4000;
    let start = lines.len().saturating_sub(MAX_ROWS);
    let slice = &lines[start..];

    const ROW_H: f32 = 15.0;

    well_sized(ui, content_h, content_h, |ui| {
        ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Truncate);
        egui::ScrollArea::vertical()
            .id_salt(id)
            .max_height(content_h)
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .show_rows(ui, ROW_H, slice.len(), |ui, range| {
                ui.spacing_mut().item_spacing.y = 0.0;
                for i in range {
                    let line = &slice[i];
                    let color = colorize(line, &pal);
                    let response = ui.add(
                        egui::Label::new(RichText::new(line).font(theme::mono(theme::FS_MONO)).color(color))
                            .truncate()
                            .sense(Sense::hover()),
                    );
                    if response.hovered() {
                        response.on_hover_text(line);
                    }
                }
            });
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Height a block occupies inside a real page at the default window size.
    ///
    /// This runs egui headlessly — no window, no GPU — using the same shape the
    /// application uses: a fixed-width page inside a scroll area that fills the
    /// available height. That is the only arrangement in which the bug below
    /// reproduces, because the inflation came from the page height being
    /// available to the wrong layout.
    fn used_height(add: impl FnOnce(&mut Ui)) -> f32 {
        let ctx = egui::Context::default();
        crate::theme::apply(&ctx, false);
        let viewport = Vec2::new(860.0, 744.0);
        let input = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, viewport)),
            ..Default::default()
        };

        let mut add = Some(add);
        let mut height = 0.0_f32;
        let _ = ctx.run(input, |ctx| {
            egui::CentralPanel::default()
                .frame(egui::Frame::NONE)
                .show(ctx, |ui| {
                    egui::ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            page(ui, |ui| {
                                if let Some(add) = add.take() {
                                    add(ui);
                                }
                                height = ui.min_rect().height();
                            });
                        });
                });
        });
        height
    }

    /// The header is an icon, two lines of text and a rule: about 77 px at this
    /// width.
    ///
    /// It used to come out at 409 px. The trailing actions were laid out with
    /// `Layout::right_to_left(Align::Center)` directly inside a top-aligned row,
    /// so egui centred that region against the full, unbounded height of the
    /// page instead of against one row — and every page in the application grew
    /// a scrollbar because of a header that filled half of it. `right_aligned`
    /// gives the region an explicit one-row-tall bound; this test is what keeps
    /// someone from "simplifying" it back.
    #[test]
    fn a_page_header_stays_one_row_tall() {
        let height = used_height(|ui| {
            page_header(ui, Icon::FileDoc, "总览", "系统当前的安全状态", |ui| {
                let _ = outline(ui, None, "按钮");
            });
        });

        assert!(
            height < 130.0,
            "page header measured {height} px; the trailing action row is being \
             centred against the page height instead of its own row"
        );
    }

    /// Same failure mode in its smallest form, without the header's text.
    #[test]
    fn a_trailing_action_does_not_stretch_a_row() {
        let height = used_height(|ui| {
            ui.horizontal_top(|ui| {
                ui.label(theme::title("标题"));
                right_aligned(ui, |ui| {
                    let _ = outline(ui, None, "按钮");
                });
            });
        });

        assert!(
            height < 80.0,
            "a single action row measured {height} px; right-aligned content is \
             growing to the height of the page"
        );
    }

    /// The budget arithmetic must never ask for a negative height: a negative
    /// allocation panics, and a zero-height list looks like a rendering bug.
    #[test]
    fn a_filling_block_never_asks_for_a_negative_height() {
        assert_eq!(budget(744.0, 300.0, 4.0, 48.0), 440.0);
        assert_eq!(budget(544.0, 100.0, 4.0, 120.0), 440.0);
        // Everything already spent: the floor applies rather than a negative
        // number, so the page scrolls instead of collapsing.
        assert_eq!(budget(744.0, 900.0, 4.0, 48.0), 48.0);
        assert_eq!(budget(744.0, 744.0, 4.0, 120.0), 120.0);
    }

    /// A page whose content is an empty state must still reach the bottom of the
    /// window. It used to stop two thirds of the way down and leave several
    /// hundred pixels of bare paper, which is what the placeholder card now
    /// covers.
    #[test]
    fn a_filling_empty_state_reaches_the_bottom_of_the_page() {
        let height = used_height(|ui| {
            empty_state_filling(
                ui,
                744.0,
                Icon::FileDoc,
                "暂无内容",
                "扫描完成后结果会显示在这里",
                Tone::Neutral,
            );
        });

        assert!(
            (height - 740.0).abs() < 8.0,
            "an empty page should end at the bottom of the viewport, measured {height} px"
        );
    }
}
