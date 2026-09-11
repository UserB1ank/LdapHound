//! App state + Elm update loop (function-style, iced 0.14).
//!
//! Layout (halloy-inspired):
//! ```text
//! Row![
//!     sidebar,                                // 顶部 filter，中间 tree，底部 Open
//!     container(PaneGrid).padding(8),         // 主内容，每 pane 含 TitleBar
//! ]
//! ```

use std::collections::HashSet;
use std::sync::Arc;

use iced::Task;
use iced::widget::pane_grid::{self, PaneGrid};
use iced::widget::{button, column, container, row, text};
use iced::{Element, Length};

use ldaphound_core::{LdapGraph, Snapshot, Tree};

use crate::message::{Message, SecretInput};
use crate::task;
use crate::view::{object_view, sidebar};

/// Right-pane kind so PaneGrid can dispatch view per pane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pane {
    Sidebar,
    Main,
}

/// Application state.
pub struct App {
    snapshot: Option<Arc<Snapshot>>,
    graph: Option<Arc<LdapGraph>>,
    tree: Option<Tree>,

    /// Two-pane layout: [Sidebar | Main] with a draggable divider.
    panes: pane_grid::State<Pane>,

    /// DNs (lowercased) of currently-expanded tree nodes.
    expanded: HashSet<String>,
    /// Selected object index, shown in the right pane.
    selected: Option<usize>,
    /// Selected ACE index within the current object's DACL.
    selected_ace: Option<usize>,
    /// Right pane active tab: 0 = Attributes, 1 = ACL, 2 = AI Analysis.
    active_tab: usize,
    /// Sidebar filter text (substring on DN / display name).
    filter: String,
    /// ACL tab: optional active trustee filter (matches AceLine.trustee
    /// verbatim). None = show all.
    acl_filter_trustee: Option<String>,
    /// ACL tab: optional active right filter (matches AceLine.right).
    acl_filter_right: Option<String>,
    /// Cached ACL display data for the currently-selected object. Rebuilt
    /// whenever the selection changes; borrowed by `view_acl` so it can
    /// hand `&str` to read-only `text_input` widgets (selectable text).
    /// Always `Some` — defaults to an empty cache when no object is
    /// selected (main_pane bails out before reading it).
    acl_cache: crate::view::object_view::AclCache,
    /// Same pattern as acl_cache but for the Attributes tab — pre-built
    /// (name, value) pairs borrowed by view_attributes so the value field
    /// can be a selectable text_input.
    attr_cache: crate::view::object_view::AttrCache,

    status: String,
    parsing: bool,
    ai_settings_open: bool,
    ai_api_key: SecretInput,
    ai_base_url: String,
    ai_question: String,
    ai_model: String,
    ai_answer: String,
    ai_running: bool,
}

pub fn new() -> App {
    let (mut panes, _first) = pane_grid::State::new(Pane::Sidebar);
    let _ = panes.split(
        pane_grid::Axis::Vertical,
        panes.panes.keys().next().copied().unwrap(),
        Pane::Main,
    );

    App {
        snapshot: None,
        graph: None,
        tree: None,
        panes,
        expanded: HashSet::new(),
        selected: None,
        selected_ace: None,
        active_tab: 0,
        filter: String::new(),
        acl_filter_trustee: None,
        acl_filter_right: None,
        acl_cache: crate::view::object_view::AclCache::default(),
        attr_cache: crate::view::object_view::AttrCache::default(),
        status: "Open a .dat snapshot or an ldapsearch LDIF dump to begin.".into(),
        parsing: false,
        ai_settings_open: false,
        ai_api_key: SecretInput::default(),
        ai_base_url: std::env::var("OPENAI_BASE_URL")
            .unwrap_or_else(|_| "https://api.openai.com/v1".into()),
        ai_question: "Find high-impact privilege paths and misconfigurations.".into(),
        ai_model: std::env::var("OPENAI_MODEL").unwrap_or_else(|_| "gpt-5.6".into()),
        ai_answer: String::new(),
        ai_running: false,
    }
}

pub fn title(app: &App) -> String {
    match &app.snapshot {
        Some(s) => format!("LdapHound — {}", s.header.server),
        None => "LdapHound".into(),
    }
}

pub fn update(app: &mut App, message: Message) -> Task<Message> {
    match message {
        Message::OpenFileClicked => {
            app.parsing = true;
            app.status = "Selecting file…".into();
            Task::perform(
                async {
                    rfd::AsyncFileDialog::new()
                        .add_filter("ADExplorer snapshot (.dat)", &["dat"])
                        .add_filter("LDAP search result (.ldif)", &["ldif", "txt", "log"])
                        .pick_file()
                        .await
                        .map(|h| h.path().to_path_buf())
                },
                Message::FileSelected,
            )
        }
        Message::FileSelected(maybe_path) => match maybe_path {
            Some(path) => {
                app.status = format!("Parsing {}…", path.display());
                app.parsing = true;
                task::parse_snapshot(path)
            }
            None => {
                app.parsing = false;
                Task::none()
            }
        },
        Message::ParseCompleted(result) => {
            app.parsing = false;
            match result {
                Ok(loaded) => {
                    let snap = loaded.snapshot;
                    app.status = format!(
                        "{} objects loaded from {}",
                        snap.objects.len(),
                        snap.header.server,
                    );
                    let tree = snap.build_tree();
                    // Tree starts fully collapsed — user expands nodes as
                    // needed via the chevrons.
                    app.tree = Some(tree);
                    app.expanded = HashSet::new();
                    app.selected = None;
                    app.selected_ace = None;
                    app.acl_filter_trustee = None;
                    app.acl_filter_right = None;
                    app.acl_cache = crate::view::object_view::AclCache::default();
                    app.attr_cache = crate::view::object_view::AttrCache::default();
                    app.filter.clear();
                    app.snapshot = Some(snap);
                    app.graph = Some(loaded.graph);
                    app.ai_answer.clear();
                    app.ai_running = false;
                }
                Err(e) => app.status = format!("Parse failed: {e}"),
            }
            Task::none()
        }
        Message::ToggleNode(dn) => {
            if app.expanded.contains(&dn) {
                app.expanded.remove(&dn);
            } else {
                app.expanded.insert(dn);
            }
            Task::none()
        }
        Message::SelectNode(i) => {
            app.selected = Some(i);
            app.selected_ace = None;
            app.acl_filter_trustee = None;
            app.acl_filter_right = None;
            // Rebuild both caches for the newly-selected object so the view
            // can borrow stable &str values for selectable text_input rows.
            if let Some(snap) = app.snapshot.as_ref() {
                if let Some(o) = snap.objects.get(i) {
                    app.acl_cache = crate::view::object_view::build_acl_cache(o, snap);
                    app.attr_cache = crate::view::object_view::build_attr_cache(o);
                }
            }
            Task::none()
        }
        Message::SelectAce(i) => {
            app.selected_ace = if app.selected_ace == Some(i) {
                None
            } else {
                Some(i)
            };
            Task::none()
        }
        Message::CopyToClipboard(s) => {
            app.status = format!("Copied {} chars", s.len());
            iced::clipboard::write(s)
        }
        Message::TabSelected(tab) => {
            app.active_tab = tab;
            Task::none()
        }
        Message::PaneResized(pane_grid::ResizeEvent { split, ratio }) => {
            app.panes.resize(split, ratio);
            Task::none()
        }
        Message::FilterChanged(s) => {
            app.filter = s;
            Task::none()
        }
        Message::SelectBySid(sid) => {
            // Find the object with this SID, select it, and expand every
            // ancestor DN so the target is visible in the tree.
            if let Some(snap) = app.snapshot.as_ref() {
                let target = snap
                    .objects
                    .iter()
                    .position(|o| o.object_sid().map(|s| s == sid).unwrap_or(false));
                if let Some(idx) = target {
                    // Expand ancestors: walk up the DN, mark each parent.
                    if let Some(dn) = snap.objects[idx].dn() {
                        let lower = dn.to_ascii_lowercase();
                        let mut start = 0usize;
                        while let Some(comma) = lower[start..].find(',') {
                            let parent_dn = &lower[start + comma + 1..];
                            app.expanded.insert(parent_dn.trim().to_string());
                            start += comma + 1;
                            // Advance to the next comma; if none, break.
                            if lower[start..].find(',').is_none() {
                                break;
                            }
                        }
                        // Also clear the filter so the target is reachable.
                        app.filter.clear();
                    }
                    // Reuse the SelectNode path (rebuild acl_cache + select).
                    app.selected = Some(idx);
                    app.selected_ace = None;
                    let obj = &snap.objects[idx];
                    app.acl_cache = crate::view::object_view::build_acl_cache(obj, snap);
                    app.attr_cache = crate::view::object_view::build_attr_cache(obj);
                }
            }
            Task::none()
        }
        Message::ToggleAclTrusteeFilter(s) => {
            // Empty string clears the filter (from the "(all)" pick_list
            // entry). Otherwise set to the selected value.
            app.acl_filter_trustee = if s.is_empty() { None } else { Some(s) };
            app.selected_ace = None;
            Task::none()
        }
        Message::ToggleAclRightFilter(s) => {
            app.acl_filter_right = if s.is_empty() { None } else { Some(s) };
            app.selected_ace = None;
            Task::none()
        }
        Message::AiSettingsToggled => {
            app.ai_settings_open = !app.ai_settings_open;
            Task::none()
        }
        Message::AiApiKeyChanged(api_key) => {
            app.ai_api_key = api_key;
            Task::none()
        }
        Message::AiBaseUrlChanged(base_url) => {
            app.ai_base_url = base_url;
            Task::none()
        }
        Message::AiQuestionChanged(question) => {
            app.ai_question = question;
            Task::none()
        }
        Message::AiModelChanged(model) => {
            app.ai_model = model;
            Task::none()
        }
        Message::AiAnalyzeClicked => {
            if app.ai_running || app.ai_question.trim().is_empty() {
                return Task::none();
            }
            let Some(graph) = app.graph.as_ref() else {
                app.ai_answer = "No LDAP graph is loaded.".into();
                return Task::none();
            };
            app.ai_running = true;
            app.ai_answer = "Analyzing the curated LDAP graph…".into();
            app.status = "AI analysis running (curated graph only; store=false)…".into();
            task::analyze_graph(
                Arc::clone(graph),
                app.ai_question.trim().to_string(),
                app.ai_api_key.expose().to_string(),
                app.ai_base_url.trim().to_string(),
                app.ai_model.trim().to_string(),
                app.selected,
            )
        }
        Message::AiAnalysisCompleted(result) => {
            app.ai_running = false;
            match result {
                Ok(answer) => {
                    app.ai_answer = answer;
                    app.status = "AI analysis completed.".into();
                }
                Err(error) => {
                    app.ai_answer = format!("AI analysis failed: {error}");
                    app.status = "AI analysis failed.".into();
                }
            }
            Task::none()
        }
    }
}

pub fn view(app: &App) -> Element<'_, Message> {
    // Top menu bar: Open .dat button + status text, pinned above everything.
    let open_btn = button(
        row![crate::icon::folder(), iced::widget::text("Open…").size(13),]
            .spacing(6)
            .align_y(iced::alignment::Vertical::Center),
    )
    .on_press_maybe(if app.parsing {
        None
    } else {
        Some(Message::OpenFileClicked)
    })
    .padding([4, 10])
    .style(|t, s| crate::theme::primary(t, s));

    let ai_settings_btn = button(
        row![
            crate::icon::gear(),
            iced::widget::text(if app.ai_settings_open {
                "Hide AI settings"
            } else {
                "AI settings"
            })
            .size(13),
        ]
        .spacing(6)
        .align_y(iced::alignment::Vertical::Center),
    )
    .on_press(Message::AiSettingsToggled)
    .padding([4, 10])
    .style(|t, s| crate::theme::secondary(t, s));

    let menu_bar = container(
        row![
            open_btn,
            ai_settings_btn,
            iced::widget::text(app.status.clone())
                .size(12)
                .color(crate::theme::dim_text()),
        ]
        .spacing(12)
        .align_y(iced::alignment::Vertical::Center),
    )
    .padding([4, 8])
    .width(Length::Fill)
    .style(|t| crate::theme::pane_title_bar(t));

    let body: Element<'_, Message> = match (&app.snapshot, &app.graph, &app.tree) {
        (Some(snap), Some(graph), Some(tree)) => {
            let expanded = &app.expanded;
            let selected = app.selected;
            let selected_ace = app.selected_ace;
            let active_tab = app.active_tab;
            let filter = &app.filter;
            let parsing = app.parsing;
            // Caches: pre-built on SelectNode; default to empty when
            // nothing is selected (main_pane bails on selected=None first).
            let acl_cache: &crate::view::object_view::AclCache = &app.acl_cache;
            let attr_cache: &crate::view::object_view::AttrCache = &app.attr_cache;
            let acl_filter_trustee = &app.acl_filter_trustee;
            let acl_filter_right = &app.acl_filter_right;

            let pane_grid: Element<'_, Message> =
                PaneGrid::new(&app.panes, move |_id, pane, _m| {
                    let element: iced::Element<'_, Message> = match pane {
                        Pane::Sidebar => {
                            sidebar::view(snap, tree, expanded, selected, filter, parsing)
                        }
                        Pane::Main => main_pane(
                            selected,
                            selected_ace,
                            active_tab,
                            snap,
                            graph,
                            attr_cache,
                            acl_cache,
                            acl_filter_trustee,
                            acl_filter_right,
                            &app.ai_question,
                            &app.ai_model,
                            &app.ai_answer,
                            app.ai_running,
                        ),
                    };
                    pane_grid::Content::new(element)
                })
                .spacing(4)
                .on_resize(8, Message::PaneResized)
                .width(Length::Fill)
                .height(Length::Fill)
                .into();

            container(pane_grid)
                .padding(8)
                .width(Length::Fill)
                .height(Length::Fill)
                .into()
        }
        _ => container(
            iced::widget::text("Open a .dat snapshot or an ldapsearch LDIF dump to begin.")
                .color(crate::theme::dim_text()),
        )
        .center(Length::Fill)
        .width(Length::Fill)
        .height(Length::Fill)
        .into(),
    };

    let mut content = iced::widget::column![menu_bar];
    if app.ai_settings_open {
        content = content.push(ai_settings_panel(app));
    }
    let content = content
        .push(body)
        .width(Length::Fill)
        .height(Length::Fill)
        .spacing(0);

    container(content)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

fn ai_settings_panel(app: &App) -> Element<'_, Message> {
    use iced::widget::{Space, text_input};

    let base_url = text_input("https://api.openai.com/v1", &app.ai_base_url)
        .on_input(Message::AiBaseUrlChanged)
        .width(Length::Fill);
    let model = text_input("Model ID", &app.ai_model)
        .on_input(Message::AiModelChanged)
        .width(Length::Fill);
    let api_key = text_input("Blank uses OPENAI_API_KEY", app.ai_api_key.expose())
        .on_input(|value| Message::AiApiKeyChanged(SecretInput::new(value)))
        .secure(true)
        .width(Length::Fill);
    let key_source = if app.ai_api_key.expose().is_empty() {
        "API key is blank: OPENAI_API_KEY will be used when you analyze"
    } else {
        "API key source: masked session value (never saved to disk)"
    };

    container(
        column![
            row![
                text("AI model configuration").size(15),
                Space::new().width(Length::Fill),
                button(text("Done").size(12))
                    .on_press(Message::AiSettingsToggled)
                    .padding([3, 8])
                    .style(|theme, status| crate::theme::secondary(theme, status)),
            ]
            .align_y(iced::alignment::Vertical::Center),
            text("OpenAI Responses API-compatible connection. Settings apply to the next analysis request.")
                .size(12)
                .color(crate::theme::dim_text()),
            column![text("API base URL").size(12), base_url].spacing(3),
            column![text("Model ID").size(12), model].spacing(3),
            column![text("API key").size(12), api_key].spacing(3),
            text(key_source).size(12).color(crate::theme::dim_text()),
            text("Security: the key stays in process memory, remote endpoints require HTTPS, redirects are disabled, and requests use store=false. The key is sent to the configured endpoint—verify it before analyzing.")
                .size(12)
                .color(crate::theme::dim_text()),
        ]
        .spacing(7),
    )
    .padding([8, 12])
    .width(Length::Fill)
    .style(|theme| crate::theme::pane_body(theme))
    .into()
}

/// Render the Main pane: a title bar with the object's display name + class,
/// then the body (Attributes / ACL tabs).
fn main_pane<'a>(
    selected: Option<usize>,
    selected_ace: Option<usize>,
    active_tab: usize,
    snap: &'a Snapshot,
    graph: &'a LdapGraph,
    attr_cache: &'a crate::view::object_view::AttrCache,
    acl_cache: &'a crate::view::object_view::AclCache,
    acl_filter_trustee: &'a Option<String>,
    acl_filter_right: &'a Option<String>,
    ai_question: &'a str,
    ai_model: &'a str,
    ai_answer: &'a str,
    ai_running: bool,
) -> Element<'a, Message> {
    let Some(idx) = selected else {
        return container(text("Select an object in the tree."))
            .center(Length::Fill)
            .width(Length::Fill)
            .height(Length::Fill)
            .into();
    };
    let Some(obj) = snap.objects.get(idx) else {
        return text("(object not found)").into();
    };

    // Title bar: display name + class badge + DN subtitle.
    let title_text = obj.display_name();
    let class = obj
        .object_classes()
        .last()
        .map(|s| s.as_str())
        .unwrap_or("?")
        .to_string();
    let dn = obj.dn().unwrap_or("").to_string();
    let title_bar = container(
        column![
            row![
                crate::icon::for_object_type(obj.object_type()),
                text(title_text).size(15),
                text(class).color(crate::theme::dim_text()),
            ]
            .spacing(8)
            .align_y(iced::alignment::Vertical::Center),
            text(dn).color(crate::theme::dim_text()),
        ]
        .spacing(2),
    )
    .padding([6, 10])
    .width(Length::Fill)
    .style(|t| crate::theme::pane_title_bar(t));

    let body = object_view::view(
        obj,
        snap,
        graph,
        selected_ace,
        active_tab,
        attr_cache,
        acl_cache,
        acl_filter_trustee.as_deref(),
        acl_filter_right.as_deref(),
        ai_question,
        ai_model,
        ai_answer,
        ai_running,
    );

    column![title_bar, body]
        .width(Length::Fill)
        .height(Length::Fill)
        .spacing(0)
        .into()
}
