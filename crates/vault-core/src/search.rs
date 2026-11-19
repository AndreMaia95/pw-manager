//! Pesquisa de entradas (ticket 06).
//!
//! Incide só sobre os metadados da entrada (título, URL e utilizador), nunca
//! sobre a palavra-passe nem as notas, e não distingue maiúsculas nem acentos.

use unicode_normalization::UnicodeNormalization;
use unicode_normalization::char::is_combining_mark;
use zeroize::Zeroizing;

use crate::entry::EntrySummary;

/// O texto de uma pesquisa, dividido em palavras já normalizadas.
pub(crate) struct Query(Vec<Zeroizing<String>>);

impl Query {
    /// Divide o texto pelos espaços. Uma palavra que seja um URL colado perde o
    /// esquema e o `www.`, como o campo URL, e um esquema ainda a ser escrito
    /// (`http:`, `https:/`) é ignorado. Sem palavras, encontra tudo.
    pub(crate) fn new(text: &str) -> Self {
        let folded = fold_case_and_accents(text);
        let words = folded
            .split_whitespace()
            .filter(|word| !is_scheme_being_typed(word))
            .map(without_url_prefix)
            .filter(|word| !word.is_empty())
            .map(|word| Zeroizing::new(word.to_owned()))
            .collect();
        Self(words)
    }

    /// Se cada palavra aparece no título, no URL ou no utilizador da entrada,
    /// não necessariamente todas no mesmo campo. No URL, o esquema e o `www.`
    /// não contam.
    pub(crate) fn matches(&self, entry: &EntrySummary) -> bool {
        let title = fold_case_and_accents(&entry.title);
        let url = fold_case_and_accents(&entry.url);
        let username = fold_case_and_accents(&entry.username);
        let fields = [title.as_str(), without_url_prefix(&url), username.as_str()];
        self.0
            .iter()
            .all(|word| fields.iter().any(|field| field.contains(word.as_str())))
    }
}

const URL_SCHEMES: [&str; 2] = ["https://", "http://"];

/// Se a palavra é o início de um esquema, já com os dois pontos (`http:`,
/// `https:/`). Sem eles, `http` é uma palavra como as outras.
fn is_scheme_being_typed(word: &str) -> bool {
    word.contains(':') && URL_SCHEMES.iter().any(|scheme| scheme.starts_with(word))
}

/// O texto sem `http://` ou `https://` à cabeça e depois sem `www.`. Recebe
/// texto já em minúsculas.
fn without_url_prefix(text: &str) -> &str {
    let text = text.trim_start();
    let text = URL_SCHEMES
        .into_iter()
        .find_map(|scheme| text.strip_prefix(scheme))
        .unwrap_or(text);
    text.strip_prefix("www.").unwrap_or(text)
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
