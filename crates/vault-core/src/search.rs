//! Pesquisa de entradas (ticket 06).
//!
//! Incide só sobre os metadados da entrada (título, URL e utilizador), nunca
//! sobre a palavra-passe nem as notas, e não distingue maiúsculas nem acentos.

use unicode_normalization::UnicodeNormalization;
use unicode_normalization::char::is_combining_mark;
use zeroize::Zeroizing;

use crate::entry::EntrySummary;

/// O texto de uma pesquisa, já normalizado.
pub(crate) struct Query(Zeroizing<String>);

impl Query {
    pub(crate) fn new(text: &str) -> Self {
        Self(fold_case_and_accents(text.trim()))
    }

    /// Se o título, o URL ou o utilizador da entrada contêm o texto pesquisado.
    pub(crate) fn matches(&self, entry: &EntrySummary) -> bool {
        [&entry.title, &entry.url, &entry.username]
            .into_iter()
            .any(|field| fold_case_and_accents(field).contains(self.0.as_str()))
    }
}

/// Minúsculas, sem acentos e sem formas de compatibilidade: decompõe (NFKD) e
/// larga as marcas combinatórias. Assim "Ç", "ç" e "c" seguido de U+0327 ficam
/// todos "c", "Ａ" fica "a" e a ligadura "ﬁ" fica "fi".
///
/// A cópia é apagada da memória ao ser largada. O espaço é reservado à cabeça
/// para que, no texto comum, não fiquem cópias para trás quando a string cresce.
fn fold_case_and_accents(text: &str) -> Zeroizing<String> {
    let mut folded = Zeroizing::new(String::with_capacity(text.len() * 2));
    folded.extend(
        text.nfkd()
            .filter(|&c| !is_combining_mark(c))
            .flat_map(char::to_lowercase),
    );
    folded
}
