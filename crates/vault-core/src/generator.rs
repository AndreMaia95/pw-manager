//! Gerador de palavras-passe e frases-passe (ticket 08).
//!
//! Toda a aleatoriedade vem do CSPRNG do SO (`getrandom`). A palavra-passe
//! gerada vai direta para a entrada e não sai do núcleo sem ser revelada
//! (ADR-0005), por isso este módulo não é público.

use std::sync::LazyLock;

use zeroize::Zeroizing;

use crate::VaultError;
use crate::cbor::{self, MapReader, MapWriter, UnknownFields};
use crate::crypto;

const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
const DIGITS: &str = "0123456789";
/// Símbolos aceites pela maioria dos sites. Ficam de fora as aspas, a barra
/// invertida, o acento grave, a barra vertical (parece um `l`) e o espaço.
const SYMBOLS: &str = "!#$%&()*+,-./:;<=>?@[]^_{}~";
/// Caracteres que se confundem uns com os outros ao ler ou escrever à mão.
const AMBIGUOUS: &str = "0O1lI";

/// O comprimento máximo de uma palavra-passe gerada.
const MAX_LENGTH: u32 = 128;
/// O número máximo de palavras de uma frase-passe gerada.
const MAX_WORDS: u32 = 20;

/// Os ajustes do gerador de uma entrada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeneratorSettings {
    /// Uma palavra-passe de `length` caracteres, com pelo menos um de cada
    /// classe ativa.
    Password {
        length: u32,
        uppercase: bool,
        lowercase: bool,
        digits: bool,
        symbols: bool,
        /// Sem `0O1lI`.
        exclude_ambiguous: bool,
    },
    /// Uma frase-passe de `word_count` palavras da lista grande da EFF,
    /// separadas por espaços (algumas palavras da lista têm hífen).
    Passphrase { word_count: u32 },
}

impl Default for GeneratorSettings {
    /// 20 caracteres com maiúsculas, minúsculas, dígitos e símbolos, sem
    /// caracteres ambíguos.
    fn default() -> Self {
        Self::Password {
            length: 20,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: true,
        }
    }
}

impl GeneratorSettings {
    /// Uma frase-passe de 6 palavras da lista grande da EFF.
    pub fn default_passphrase() -> Self {
        Self::Passphrase { word_count: 6 }
    }

    /// Se é possível gerar com estes ajustes: pelo menos uma classe ativa,
    /// comprimento de 1 a [`MAX_LENGTH`] e não menor do que o número de
    /// classes ativas (cada uma aparece pelo menos uma vez), ou de 1 a
    /// [`MAX_WORDS`] palavras.
    pub(crate) fn is_valid(&self) -> bool {
        match self {
            Self::Password {
                length,
                uppercase,
                lowercase,
                digits,
                symbols,
                exclude_ambiguous: _,
            } => {
                let classes = [uppercase, lowercase, digits, symbols]
                    .into_iter()
                    .filter(|active| **active)
                    .count() as u32;
                classes > 0 && (classes..=MAX_LENGTH).contains(length)
            }
            Self::Passphrase { word_count } => (1..=MAX_WORDS).contains(word_count),
        }
    }
}

/// Os ajustes do gerador guardados numa entrada, no campo `generator`.
///
/// O mapa nasceu depois do primeiro vetor da versão 1.0, por isso todos os
/// campos seguem a ordem da chave codificada (ADR-0008). Os campos que esta
/// versão não conhece são preservados. Ajustes que esta versão não consegue
/// usar (um modo, `kind`, que não conhece, ou um modo conhecido com campos em
/// falta, de outro tipo ou fora dos seus limites, como os escreveria uma
/// versão mais nova que os alargasse) são guardados em bruto, tal como vieram,
/// e o gerador usa os ajustes de omissão até serem dados outros.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StoredSettings {
    Usable {
        settings: GeneratorSettings,
        unknown: UnknownFields,
    },
    Unusable(Zeroizing<Vec<u8>>),
}

impl StoredSettings {
    pub(crate) fn new(settings: GeneratorSettings) -> Self {
        Self::Usable {
            settings,
            unknown: UnknownFields::default(),
        }
    }

    /// Os ajustes com que se gera: os guardados, ou os de omissão se esta
    /// versão não os conseguir usar.
    pub(crate) fn settings(&self) -> GeneratorSettings {
        match self {
            Self::Usable { settings, .. } => settings.clone(),
            Self::Unusable(_) => GeneratorSettings::default(),
        }
    }

    pub(crate) fn encode(&self) -> Zeroizing<Vec<u8>> {
        let (settings, unknown) = match self {
            Self::Usable { settings, unknown } => (settings, unknown),
            Self::Unusable(raw) => return raw.clone(),
        };
        let mut map = MapWriter::new();
        match settings {
            GeneratorSettings::Password {
                length,
                uppercase,
                lowercase,
                digits,
                symbols,
                exclude_ambiguous,
            } => {
                map.added("kind", PASSWORD);
                map.added("length", length);
                map.added("uppercase", uppercase);
                map.added("lowercase", lowercase);
                map.added("digits", digits);
                map.added("symbols", symbols);
                map.added("exclude_ambiguous", exclude_ambiguous);
            }
            GeneratorSettings::Passphrase { word_count } => {
                map.added("kind", PASSPHRASE);
                map.added("word_count", word_count);
            }
        }
        map.unknown(unknown);
        map.finish()
    }

    /// Lê o campo `generator` de uma entrada. `None` só se não for um mapa
    /// bem formado com chaves em texto.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let map = MapReader::parse(bytes)?;
        Some(
            Self::decode_usable(map)
                .unwrap_or_else(|| Self::Unusable(Zeroizing::new(bytes.to_vec()))),
        )
    }

    /// Os ajustes de `map`, se esta versão os conseguir usar.
    fn decode_usable(mut map: MapReader) -> Option<Self> {
        let kind: String = cbor::decode_value(map.take("kind")?)?;
        let settings = match kind.as_str() {
            PASSWORD => GeneratorSettings::Password {
                length: cbor::decode_value(map.take("length")?)?,
                uppercase: cbor::decode_value(map.take("uppercase")?)?,
                lowercase: cbor::decode_value(map.take("lowercase")?)?,
                digits: cbor::decode_value(map.take("digits")?)?,
                symbols: cbor::decode_value(map.take("symbols")?)?,
                exclude_ambiguous: cbor::decode_value(map.take("exclude_ambiguous")?)?,
            },
            PASSPHRASE => GeneratorSettings::Passphrase {
                word_count: cbor::decode_value(map.take("word_count")?)?,
            },
            _ => return None,
        };
        settings.is_valid().then(|| Self::Usable {
            settings,
            unknown: map.into_unknown(),
        })
    }
}

const PASSWORD: &str = "password";
const PASSPHRASE: &str = "passphrase";

/// A lista grande da EFF (7776 palavras, uma por cada lançamento de 5 dados),
/// tal como publicada em
/// <https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt>
/// (SHA-256 `addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e`).
const EFF_LARGE_WORDLIST: &str = include_str!("eff_large_wordlist.txt");

/// Gera uma palavra-passe com `settings`.
pub(crate) fn generate(settings: &GeneratorSettings) -> Result<Zeroizing<String>, VaultError> {
    if !settings.is_valid() {
        return Err(VaultError::InvalidGeneratorSettings);
    }
    match settings {
        GeneratorSettings::Password {
            length,
            uppercase,
            lowercase,
            digits,
            symbols,
            exclude_ambiguous,
        } => {
            let classes: Vec<Vec<char>> = [
                (*uppercase, UPPERCASE),
                (*lowercase, LOWERCASE),
                (*digits, DIGITS),
                (*symbols, SYMBOLS),
            ]
            .into_iter()
            .filter(|(active, _)| *active)
            .map(|(_, class)| {
                class
                    .chars()
                    .filter(|c| !(*exclude_ambiguous && AMBIGUOUS.contains(*c)))
                    .collect()
            })
            .collect();
            random_password(*length as usize, &classes)
        }
        GeneratorSettings::Passphrase { word_count } => passphrase(*word_count as usize),
    }
}

/// `word_count` palavras da lista grande da EFF, escolhidas uniformemente.
fn passphrase(word_count: usize) -> Result<Zeroizing<String>, VaultError> {
    let words = &*EFF_WORDS;
    // Com a capacidade toda reservada, a frase não é copiada ao crescer, o que
    // deixaria cópias por apagar na memória.
    let longest = words
        .iter()
        .map(|word| word.len())
        .max()
        .unwrap_or_default();
    let mut phrase = Zeroizing::new(String::with_capacity(word_count * (longest + 1)));
    for i in 0..word_count {
        if i > 0 {
            phrase.push(' ');
        }
        phrase.push_str(words[random_below(words.len())?]);
    }
    Ok(phrase)
}

/// As palavras da lista, sem os números dos dados.
static EFF_WORDS: LazyLock<Vec<&str>> = LazyLock::new(|| {
    EFF_LARGE_WORDLIST
        .lines()
        .map(|line| line.split_once('\t').expect("número e palavra").1)
        .collect()
});

/// Uma palavra-passe de `length` caracteres escolhidos uniformemente entre
/// todos os de `classes`. As que não tiverem pelo menos um de cada classe são
/// descartadas e geradas de novo: assim todas as palavras-passe válidas são
/// igualmente prováveis.
fn random_password(length: usize, classes: &[Vec<char>]) -> Result<Zeroizing<String>, VaultError> {
    let alphabet: Vec<char> = classes.concat();
    loop {
        let mut candidate = Zeroizing::new(String::with_capacity(length));
        for _ in 0..length {
            candidate.push(alphabet[random_below(alphabet.len())?]);
        }
        if classes
            .iter()
            .all(|class| candidate.chars().any(|c| class.contains(&c)))
        {
            return Ok(candidate);
        }
    }
}

/// Um número uniforme em `0..n`, por rejeição: os valores do topo de `u32`
/// que dariam mais peso aos primeiros números são descartados.
fn random_below(n: usize) -> Result<usize, VaultError> {
    let n = u32::try_from(n).expect("os alfabetos e a lista de palavras cabem em u32");
    assert!(n > 0, "não há nada por onde escolher");
    let zone = u32::MAX - (u32::MAX % n);
    loop {
        let value = u32::from_le_bytes(crypto::random_bytes()?);
        if value < zone {
            return Ok((value % n) as usize);
        }
    }
}

#[cfg(test)]
mod tests {
    //! Testes estatísticos simples. Os limites estão a cerca de 7 desvios
    //! padrão do esperado: um gerador correto quase nunca falha, e um
    //! enviesado por um fator de poucos por cento falha sempre.

    use std::collections::HashMap;

    use super::*;

    const SAMPLES: usize = 20_000;

    fn default_passwords() -> Vec<Zeroizing<String>> {
        let settings = GeneratorSettings::default();
        (0..SAMPLES).map(|_| generate(&settings).unwrap()).collect()
    }

    /// O qui-quadrado de `counts` contra uma distribuição uniforme, e se fica
    /// abaixo de `k - 1 + 7·√(2(k - 1))`, com `k` categorias.
    fn looks_uniform(counts: &[usize]) -> bool {
        let total: usize = counts.iter().sum();
        let expected = total as f64 / counts.len() as f64;
        let chi_squared: f64 = counts
            .iter()
            .map(|&count| (count as f64 - expected).powi(2) / expected)
            .sum();
        let df = (counts.len() - 1) as f64;
        chi_squared < df + 7.0 * (2.0 * df).sqrt()
    }

    fn class_of(c: char) -> usize {
        [UPPERCASE, LOWERCASE, DIGITS, SYMBOLS]
            .iter()
            .position(|class| class.contains(c))
            .expect("todos os caracteres são de uma classe")
    }

    #[test]
    fn the_characters_of_each_class_are_equally_likely() {
        let mut counts: HashMap<char, usize> = HashMap::new();
        for password in default_passwords() {
            for c in password.chars() {
                *counts.entry(c).or_default() += 1;
            }
        }

        let expected_sizes = [24, 25, 8, 27];
        for (class, expected_size) in [UPPERCASE, LOWERCASE, DIGITS, SYMBOLS]
            .into_iter()
            .zip(expected_sizes)
        {
            let available: Vec<char> = class.chars().filter(|c| !AMBIGUOUS.contains(*c)).collect();
            assert_eq!(available.len(), expected_size);
            let class_counts: Vec<usize> = available
                .iter()
                .map(|c| counts.get(c).copied().unwrap_or_default())
                .collect();
            assert!(looks_uniform(&class_counts), "{class}: {class_counts:?}");
        }
        assert!(!counts.keys().any(|c| AMBIGUOUS.contains(*c)));
    }

    /// Escolher primeiro um carácter de cada classe e depois o resto poria as
    /// classes sempre nas mesmas posições. Na primeira e na última posição,
    /// cada classe tem de aparecer o mesmo número de vezes.
    #[test]
    fn the_classes_are_spread_over_every_position() {
        let mut first = [0usize; 4];
        let mut last = [0usize; 4];
        for password in default_passwords() {
            first[class_of(password.chars().next().unwrap())] += 1;
            last[class_of(password.chars().last().unwrap())] += 1;
        }

        for class in 0..4 {
            let (a, b) = (first[class] as f64, last[class] as f64);
            // A diferença de duas contagens independentes com a mesma média
            // tem desvio padrão de cerca de √(a + b).
            assert!((a - b).abs() < 7.0 * (a + b).sqrt(), "{first:?} {last:?}");
        }
        // Cada classe aparece numa posição pelo menos tanto como a sua parte
        // do alfabeto (84 caracteres) e as menores um pouco mais, porque as
        // palavras-passe sem alguma classe são geradas de novo.
        let share = |count: usize| count as f64 / SAMPLES as f64;
        assert!(
            share(first[0]) > 0.24 && share(first[0]) < 0.32,
            "{first:?}"
        );
        assert!(
            share(first[1]) > 0.25 && share(first[1]) < 0.33,
            "{first:?}"
        );
        assert!(
            share(first[2]) > 0.08 && share(first[2]) < 0.14,
            "{first:?}"
        );
        assert!(
            share(first[3]) > 0.27 && share(first[3]) < 0.35,
            "{first:?}"
        );
    }

    #[test]
    fn without_excluding_ambiguous_characters_they_appear_too() {
        let settings = GeneratorSettings::Password {
            length: 20,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: false,
            exclude_ambiguous: false,
        };
        let mut seen = String::new();
        for _ in 0..1_000 {
            seen.push_str(&generate(&settings).unwrap());
        }
        assert!(AMBIGUOUS.chars().all(|c| seen.contains(c)));
        assert!(!seen.chars().any(|c| SYMBOLS.contains(c)));
    }

    #[test]
    fn every_active_class_appears_even_when_the_password_is_as_short_as_its_classes() {
        let settings = GeneratorSettings::Password {
            length: 4,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: true,
        };
        for _ in 0..1_000 {
            let password = generate(&settings).unwrap();
            let mut classes: Vec<usize> = password.chars().map(class_of).collect();
            classes.sort();
            assert_eq!(classes, [0, 1, 2, 3], "{}", *password);
        }
    }

    /// As 7776 palavras divididas pelo primeiro dado: 6 grupos de 1296.
    #[test]
    fn the_words_of_a_passphrase_are_equally_likely() {
        assert_eq!(EFF_WORDS.len(), 7776);
        let first_die: HashMap<&str, usize> = EFF_LARGE_WORDLIST
            .lines()
            .map(|line| line.split_once('\t').unwrap())
            .map(|(dice, word)| (word, (dice.as_bytes()[0] - b'1') as usize))
            .collect();

        let mut counts = [0usize; 6];
        let settings = GeneratorSettings::Passphrase { word_count: 6 };
        for _ in 0..SAMPLES {
            let phrase = generate(&settings).unwrap();
            for word in phrase.split(' ') {
                counts[first_die[word]] += 1;
            }
        }
        assert!(looks_uniform(&counts), "{counts:?}");
    }

    #[test]
    fn random_below_is_uniform_for_a_count_that_does_not_divide_2_to_the_32() {
        let mut counts = [0usize; 7];
        for _ in 0..70_000 {
            counts[random_below(7).unwrap()] += 1;
        }
        assert!(looks_uniform(&counts), "{counts:?}");
    }
}
