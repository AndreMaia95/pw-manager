//! Pesquisa de entradas por título, URL e utilizador (ticket 06, ADR-0005).

mod common;

use common::{PASSWORD, TestEnv};
use vault_core::{EntryFields, EntryState, EntrySummary, Vault, VaultError};

fn new_vault() -> Vault {
    TestEnv::new().device().create_vault(PASSWORD)
}

fn entry(title: &str, url: &str, username: &str) -> EntryFields {
    EntryFields {
        title: title.to_owned(),
        url: url.to_owned(),
        username: username.to_owned(),
        password: "palavra-passe".to_owned(),
        notes: "notas".to_owned(),
    }
}

/// Os títulos das entradas encontradas por `query`, pela ordem devolvida.
fn titles_found(vault: &Vault, query: &str) -> Vec<String> {
    vault
        .search(query)
        .unwrap()
        .into_iter()
        .map(|entry| entry.title)
        .collect()
}

#[test]
fn part_of_a_title_finds_the_entry_whatever_the_case() {
    let vault = new_vault();
    vault
        .create_entry(entry("GitHub", "https://github.com", "andre"))
        .unwrap();
    vault
        .create_entry(entry("Banco", "https://bank.pt", "andre"))
        .unwrap();

    assert_eq!(titles_found(&vault, "tHUb"), ["GitHub"]);
}

#[test]
fn part_of_a_url_or_a_username_finds_the_entry() {
    let vault = new_vault();
    vault
        .create_entry(entry(
            "Trabalho",
            "https://intranet.Empresa.pt/login",
            "andre",
        ))
        .unwrap();
    vault
        .create_entry(entry("Correio", "https://mail.example.org", "Maria.Silva"))
        .unwrap();
    vault
        .create_entry(entry("Banco", "https://bank.pt", "andre"))
        .unwrap();

    assert_eq!(titles_found(&vault, "empresa.pt"), ["Trabalho"]);
    assert_eq!(titles_found(&vault, "maria.s"), ["Correio"]);
}

#[test]
fn accents_are_ignored_on_either_side() {
    let vault = new_vault();
    vault
        .create_entry(entry("Segurança Social", "https://seg-social.pt", "andre"))
        .unwrap();
    // "Cafe" com o acento como carácter combinatório (U+0301), como o macOS
    // às vezes escreve nomes.
    vault
        .create_entry(entry("Cafe\u{301} Central", "https://cafe.pt", "andre"))
        .unwrap();
    vault
        .create_entry(entry("Banco", "https://bank.pt", "joão"))
        .unwrap();

    assert_eq!(titles_found(&vault, "seguranca"), ["Segurança Social"]);
    assert_eq!(titles_found(&vault, "SEGURANÇA"), ["Segurança Social"]);
    assert_eq!(
        titles_found(&vault, "café central"),
        ["Cafe\u{301} Central"]
    );
    assert_eq!(titles_found(&vault, "JOAO"), ["Banco"]);
    assert_eq!(titles_found(&vault, "jóão"), ["Banco"]);
}

#[test]
fn text_only_in_the_password_or_the_notes_finds_nothing() {
    let vault = new_vault();
    vault
        .create_entry(EntryFields {
            password: "zebra-violeta-42".to_owned(),
            notes: "códigos de recuperação na gaveta".to_owned(),
            ..entry("GitHub", "https://github.com", "andre")
        })
        .unwrap();

    assert_eq!(vault.search("zebra"), Ok(vec![]));
    assert_eq!(vault.search("violeta-42"), Ok(vec![]));
    assert_eq!(vault.search("gaveta"), Ok(vec![]));
    assert_eq!(vault.search("recuperacao"), Ok(vec![]));
}

#[test]
fn results_carry_only_the_entry_metadata() {
    let vault = new_vault();
    let id = vault
        .create_entry(entry("GitHub", "https://github.com/login", "andre"))
        .unwrap();

    assert_eq!(
        vault.search("github"),
        Ok(vec![EntrySummary {
            id,
            title: "GitHub".to_owned(),
            url: "https://github.com/login".to_owned(),
            username: "andre".to_owned(),
            state: EntryState::Active,
        }])
    );
}

#[test]
fn an_empty_query_finds_every_entry_in_listing_order() {
    let vault = new_vault();
    vault
        .create_entry(entry("Correio", "https://mail.example.org", "andre"))
        .unwrap();
    vault
        .create_entry(entry("banco", "https://bank.pt", "andre"))
        .unwrap();

    assert_eq!(titles_found(&vault, ""), ["banco", "Correio"]);
    assert_eq!(titles_found(&vault, "   "), ["banco", "Correio"]);
    assert_eq!(vault.search(""), vault.list_entries());
}

#[test]
fn a_locked_vault_cannot_be_searched() {
    let vault = new_vault();
    vault
        .create_entry(entry("GitHub", "https://github.com", "andre"))
        .unwrap();
    vault.lock();

    assert_eq!(vault.search("github"), Err(VaultError::Locked));
}

#[test]
fn compatibility_forms_and_special_capitals_are_folded_too() {
    let vault = new_vault();
    vault
        .create_entry(entry(
            "İstanbul Kart",
            "https://istanbulkart.com.tr",
            "andre",
        ))
        .unwrap();
    // Letras de largura total e a ligadura "ﬁ" (U+FB01), como vêm às vezes
    // coladas de PDFs.
    vault
        .create_entry(entry("ＮＡＳ", "https://192.168.1.10", "andre"))
        .unwrap();
    vault
        .create_entry(entry("Notiﬁcações", "https://notify.example.org", "andre"))
        .unwrap();

    assert_eq!(titles_found(&vault, "istanbul"), ["İstanbul Kart"]);
    assert_eq!(titles_found(&vault, "nas"), ["ＮＡＳ"]);
    assert_eq!(titles_found(&vault, "notificacoes"), ["Notiﬁcações"]);
}

#[test]
fn the_url_scheme_and_www_prefix_are_not_searched() {
    let vault = new_vault();
    vault
        .create_entry(entry("Banco", "HTTPS://www.bank.pt/login", "andre"))
        .unwrap();
    vault
        .create_entry(entry("Router", "http://192.168.1.1", "admin"))
        .unwrap();
    vault
        .create_entry(entry("WWW Admin", "https://painel.example.org", "andre"))
        .unwrap();

    for query in ["http", "https", "s://", "://"] {
        assert_eq!(titles_found(&vault, query), [""; 0], "pesquisa {query:?}");
    }
    // O título não é um URL: "www" continua a encontrá-lo.
    assert_eq!(titles_found(&vault, "www"), ["WWW Admin"]);
    assert_eq!(titles_found(&vault, "bank.pt/log"), ["Banco"]);
}

#[test]
fn a_pasted_url_finds_its_entry_whatever_the_scheme() {
    let vault = new_vault();
    vault
        .create_entry(entry("Banco", "https://bank.pt/login", "andre"))
        .unwrap();

    assert_eq!(titles_found(&vault, "https://www.bank.pt/login"), ["Banco"]);
    assert_eq!(titles_found(&vault, "http://bank.pt"), ["Banco"]);
    assert_eq!(titles_found(&vault, "www.bank"), ["Banco"]);
}

#[test]
fn every_word_must_appear_in_some_field_but_not_all_in_the_same_one() {
    let vault = new_vault();
    vault
        .create_entry(entry("GitHub", "https://github.com/login", "andre"))
        .unwrap();
    vault
        .create_entry(entry("GitLab", "https://gitlab.com", "maria"))
        .unwrap();
    vault
        .create_entry(entry("Banco", "https://bank.pt", "andre"))
        .unwrap();

    assert_eq!(titles_found(&vault, "git andre"), ["GitHub"]);
    assert_eq!(titles_found(&vault, "  andre \t GIT  "), ["GitHub"]);
    assert_eq!(titles_found(&vault, "git"), ["GitHub", "GitLab"]);
    assert_eq!(titles_found(&vault, "git maria lab"), ["GitLab"]);
    assert_eq!(titles_found(&vault, "git pedro"), [""; 0]);
    assert_eq!(titles_found(&vault, "https://github.com andre"), ["GitHub"]);
}

#[test]
fn a_scheme_still_being_typed_is_ignored_like_a_complete_one() {
    let vault = new_vault();
    vault
        .create_entry(entry("GitHub", "https://github.com", "andre"))
        .unwrap();
    vault
        .create_entry(entry("Banco", "https://bank.pt", "andre"))
        .unwrap();

    for query in ["http:", "http:/", "https:", "HTTPS:/", "https://"] {
        assert_eq!(
            titles_found(&vault, query),
            ["Banco", "GitHub"],
            "pesquisa {query:?}"
        );
        assert_eq!(
            titles_found(&vault, &format!("{query} git")),
            ["GitHub"],
            "pesquisa {query:?} git"
        );
    }
    // Sem os dois pontos ainda não é um esquema: é uma palavra como as outras.
    assert_eq!(titles_found(&vault, "http"), [""; 0]);
}
