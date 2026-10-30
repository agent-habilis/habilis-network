use crate::snapshot::Snapshot;
use crate::ui;
use std::fmt;
use visage_rust_tui::component::{Component, Step};
use visage_rust_tui::signal::Signal;

/// The root component's state: the snapshot it reads on every step.
pub struct UiComponent {
    pub(crate) snapshot: Signal<Snapshot>,
}

impl Component for UiComponent {
    fn step(&mut self) -> Option<Step> {
        let current = self.snapshot.get();
        Some(Step::View(ui::render(&current)))
    }
}

impl fmt::Debug for UiComponent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UiComponent")
            .finish_non_exhaustive()
    }
}
