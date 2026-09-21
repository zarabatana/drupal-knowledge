# Third-Party Notices

Drupal Knowledge Community is licensed under the Apache License, Version 2.0
(`LICENSE`). That licence covers the **original** material in this repository:
the Python source under `scripts/`, `collectors/` and `dk`; the JSON schemas
under `schema/` and `public-api/`; the taxonomy; the test suites and the
synthetic fixtures under `tests/`; the website templates, stylesheet and
search script under `public-site/`; the reviewed knowledge records, rules,
context and solved cases written by the maintainers; and the documentation.

**The root Apache-2.0 licence does not relicense anything acquired from a
third party.** Everything the acquisition engine fetched from a registered
source is redistributed here under the terms its publisher declares, with
attribution, and stays under those terms inside this repository. This
document is the human-readable form of the machine-readable manifest
`THIRD_PARTY_LICENSES.json`, which lists every redistributed file with its
SHA-256, its origin and the evidence for the licence that applies;
`scripts/test_community_boundary.py` fails if a snapshot exists that the
manifest does not list.

No copyright owner is asserted for the original material. It is published
as *Drupal Knowledge Community, maintained by Zarabatana*.

The maintainers are not lawyers. Every licence statement below rests on a
publisher's published terms, quoted and dated in §1; where a fact could not
be established the entry says so.

## 1. Evidence

**E1 — Drupal.org Terms of Service, section B (Content)**  
https://www.drupal.org/terms (read 2026-09-21)
> Content, including user-generated content like comments and discussions (except for the code) on the Website is licensed under Creative Commons License, Attribution-ShareAlike 2.0
> All code on Drupal.org is licensed under the GNU General Public License version 2 or later.
> Drupal is a registered trademark of Dries Buytaert.

**E2 — Drupal.org Licensing page**  
https://www.drupal.org/about/licensing (read 2026-09-21)
> Drupal, and all contributed files that are derivative works of Drupal hosted on Drupal.org, are licensed under the GNU General Public License, version 2 or later.
> All Drupal contributors retain copyright on their code, but agree to release it under the same license as Drupal.
> If you commit that module or theme to a Drupal Git repository, however, then all parts of it must be under the GPL version 2 or later.
> All content on the Drupal.org itself is copyrighted by its original contributors, and is licensed under the Creative Commons Attribution-ShareAlike license 2.0.

**E3 — api.drupal.org site footer, as captured inside this repository's own snapshots**  
https://api.drupal.org/api/drupal/deprecated/9 (read 2026-09-21)
Present in this repository: `sources/snapshots/drupal-api-deprecated-9-p0/ … -p4 (raw HTML, footer text)`
> All source code and documentation on this site is released under the terms of the GNU General Public License, version 2 and later.
> Drupal is a registered trademark of Dries Buytaert.

**E4 — Drupal core core/COPYRIGHT.txt (11.x)**  
https://git.drupalcode.org/project/drupal/-/raw/11.x/core/COPYRIGHT.txt (read 2026-09-21)
> All Drupal code is Copyright 2001 - present by the original authors.
> This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

**E5 — coding_standards project repository on git.drupalcode.org — no licence file of its own**  
https://git.drupalcode.org/project/coding_standards (read 2026-09-21)
- Repository root contains docs/, README.md, mkdocs.yml, logo.png, .gitlab-ci.yml, .gitignore, .cspell-project-words.txt — no LICENSE file.
- GitLab project API reports license: null, license_url: null.
- README.md and mkdocs.yml contain no licence or copyright statement.
- The rendered pages site (project.pages.drupalcode.org/coding_standards/) carries no licence statement; it is generated from this repository (Material for MkDocs).
Resolution: The repository is a Drupal Git repository hosted by Drupal.org; per E2 all parts of a project committed to a Drupal Git repository must be under GPL-2.0-or-later. No project-level statement overrides that.

Two licences therefore apply to acquired material:

- **CC-BY-SA-2.0** — https://creativecommons.org/licenses/by-sa/2.0/ — attribution
  required; share-alike. Adaptations must be distributed under the same or a compatible licence. The snapshot subtree is kept separable from the Apache-2.0 original work by directory.
- **GPL-2.0-or-later** — https://www.gnu.org/licenses/old-licenses/gpl-2.0.html —
  Copyleft: redistribution must preserve the licence and the copyright notice (E4). Stored here as provenance text only — never compiled, imported, executed or modified.

Attribution for all of it: **Drupal.org and its original contributors (the
Drupal community)** for site content; **Drupal — the original authors (Drupal
core contributors)** for core source and api.drupal.org documentation, in the
whole-work form Drupal core itself uses (E4). Each snapshot's origin URLs are
recorded in `sources/registry.json`, each derived record carries its
`canonical_url` or `source_url`, and each reviewed record cites the snapshot
hash it quotes.

## 2. Source snapshots — `sources/snapshots/`

Snapshots are immutable, content-addressed copies of what a registered
source served at acquisition time, normalized to text. They exist so that
every derived record and every reviewed rule can be re-verified against
exactly the bytes it was reviewed against; `dk validate` re-reads them and
`dk provenance` walks to them. They are the provenance layer, not a
documentation mirror. Nothing is redistributed from a source that is not
registered in `sources/registry.json`.

Classification is by the domain the bytes were **actually fetched from**
(`fetch_url` where present, otherwise the canonical URL), because
Drupal-related addresses do not all carry the same terms:

| Fetched from | Licence | Basis |
|---|---|---|
| `www.drupal.org` (docs, project pages, listings, api-d7 JSON) | CC-BY-SA-2.0 | E1, E2 — Drupal.org site content |
| `updates.drupal.org` (release-history XML) | CC-BY-SA-2.0 | E1 — a drupal.org service of the same Website; predominantly factual release metadata |
| `api.drupal.org` (generated documentation, source views) | GPL-2.0-or-later | E3 — the site's own footer declares all its source code and documentation GPL-2.0-or-later |
| `git.drupalcode.org/project/drupal` (core source at a pinned tag) | GPL-2.0-or-later | E2, E4 — Drupal core |
| `project.pages.drupalcode.org/coding_standards` (rendered project docs) | GPL-2.0-or-later | E2, E5 — Drupal Git repository content with no project-level licence of its own |

Totals: 34 source families, 37 files, 2,018,654 bytes —
26 files CC-BY-SA-2.0, 11 files GPL-2.0-or-later.

### 2.1 Resolved questions

**drupalcode.org project-level licence.** `drupal-coding-standards-current`
is rendered from `git.drupalcode.org/project/coding_standards`. That
repository has no LICENSE file, its GitLab project metadata reports no
licence, and neither its README, its `mkdocs.yml` nor the rendered site
carries a licence statement (E5). It is a Drupal.org project in a Drupal Git
repository, and Drupal.org's policy is that *all parts* of such a repository
are GPL-2.0-or-later (E2). It is therefore recorded as GPL-2.0-or-later, not
as CC BY-SA site content. The companion `drupal-coding-standards-project`
snapshot is the Drupal.org *project page*, which is site content (CC-BY-SA-2.0).

**api.drupal.org attribution granularity.** api.drupal.org pages are
generated from Drupal core doc comments and declare themselves
GPL-2.0-or-later (E3). Drupal core attributes its code to "the original
authors" as a whole (E4) and carries no per-file or per-author copyright
lines, so there is no finer-grained notice to preserve. The whole-work
attribution "Drupal — the original authors (Drupal core contributors)" is
the required and sufficient form, and is what this repository uses.

### 2.2 Per-family manifest

| Source id | Fetched from | Content / normalisation | Licence | Evidence | Files | Bytes |
|---|---|---|---|---|---:|---:|
| `drupal-api-11` | api.drupal.org | html / html_text | GPL-2.0-or-later | E3, E4 | 1 | 1,124 |
| `drupal-apis-guide` | www.drupal.org | html / html_text | CC-BY-SA-2.0 | E1, E2 | 1 | 7,624 |
| `drupal-core-releases` | updates.drupal.org | xml / raw_text | CC-BY-SA-2.0 | E1, E2 | 2 | 1,083,344 |
| `drupal-core-change-record-policy` | www.drupal.org | html / html_text | CC-BY-SA-2.0 | E1, E2 | 1 | 2,795 |
| `drupal-core-change-records` | www.drupal.org | html / html_text | CC-BY-SA-2.0 | E1, E2 | 2 | 9,352 |
| `drupal-security-core` | www.drupal.org | html / html_text | CC-BY-SA-2.0 | E1, E2 | 1 | 6,760 |
| `drupal-security-contrib` | www.drupal.org | html / html_text | CC-BY-SA-2.0 | E1, E2 | 2 | 13,950 |
| `drupal-security-psa` | www.drupal.org | html / html_text | CC-BY-SA-2.0 | E1, E2 | 1 | 5,421 |
| `drupal-secure-code` | www.drupal.org | html / html_text | CC-BY-SA-2.0 | E1, E2 | 1 | 5,603 |
| `drupal-coding-standards-project` | www.drupal.org | html / html_text | CC-BY-SA-2.0 | E1, E2 | 1 | 3,085 |
| `drupal-coding-standards-current` | project.pages.drupalcode.org | html / html_text | GPL-2.0-or-later | E2, E5 | 1 | 653 |
| `drupal-coding-standards-change-records` | www.drupal.org | html / html_text | CC-BY-SA-2.0 | E1, E2 | 1 | 972 |
| `drupal-update-project-release-semantics` | git.drupalcode.org | html / html_text | GPL-2.0-or-later | E2, E4 | 1 | 6,972 |
| `drupal-update-status-security-semantics` | git.drupalcode.org | html / html_text | GPL-2.0-or-later | E2, E4 | 1 | 23,273 |
| `drupal-update-manager-interface-semantics` | git.drupalcode.org | html / html_text | GPL-2.0-or-later | E2, E4 | 1 | 4,814 |
| `drupal-contrib-token-releases` | updates.drupal.org | xml / raw_text | CC-BY-SA-2.0 | E1, E2 | 1 | 24,195 |
| `drupal-contrib-pathauto-releases` | updates.drupal.org | xml / raw_text | CC-BY-SA-2.0 | E1, E2 | 1 | 25,638 |
| `drupal-security-advisories-core` | www.drupal.org | json / raw_text | CC-BY-SA-2.0 | E1, E2 | 1 | 154,005 |
| `drupal-security-advisories-recent` | www.drupal.org | json / raw_text | CC-BY-SA-2.0 | E1, E2 | 1 | 82,719 |
| `drupal-upgrade-process-overview` | www.drupal.org | html / html_text | CC-BY-SA-2.0 | E1, E2 | 1 | 2,439 |
| `drupal-upgrade-9-to-10` | www.drupal.org | html / html_text | CC-BY-SA-2.0 | E1, E2 | 1 | 11,408 |
| `drupal-upgrade-10-to-11` | www.drupal.org | html / html_text | CC-BY-SA-2.0 | E1, E2 | 1 | 6,736 |
| `drupal-upgrade-11-to-12` | www.drupal.org | html / html_text | CC-BY-SA-2.0 | E1, E2 | 1 | 4,916 |
| `drupal-php-requirements` | www.drupal.org | html / html_text | CC-BY-SA-2.0 | E1, E2 | 1 | 8,533 |
| `drupal-api-deprecated-9-p0` | api.drupal.org | html / raw_text | GPL-2.0-or-later | E3, E4 | 1 | 84,950 |
| `drupal-api-deprecated-9-p1` | api.drupal.org | html / raw_text | GPL-2.0-or-later | E3, E4 | 1 | 83,376 |
| `drupal-api-deprecated-9-p2` | api.drupal.org | html / raw_text | GPL-2.0-or-later | E3, E4 | 1 | 80,452 |
| `drupal-api-deprecated-9-p3` | api.drupal.org | html / raw_text | GPL-2.0-or-later | E3, E4 | 1 | 82,298 |
| `drupal-api-deprecated-9-p4` | api.drupal.org | html / raw_text | GPL-2.0-or-later | E3, E4 | 1 | 58,250 |
| `drupal-core-change-notices` | www.drupal.org | json / raw_text | CC-BY-SA-2.0 | E1, E2 | 1 | 73,477 |
| `drupal-trusted-host-settings` | www.drupal.org | html / html_text | CC-BY-SA-2.0 | E1, E2 | 1 | 10,027 |
| `drupal-internal-page-cache` | www.drupal.org | html / html_text | CC-BY-SA-2.0 | E1, E2 | 1 | 3,903 |
| `drupal-cache-tags` | www.drupal.org | html / html_text | CC-BY-SA-2.0 | E1, E2 | 1 | 9,711 |
| `drupal-default-settings-php` | api.drupal.org | html / html_text | GPL-2.0-or-later | E3, E4 | 1 | 35,879 |

The five `drupal-api-deprecated-9-p*` snapshots are raw api.drupal.org HTML
and therefore also carry that site's own page markup, including its
analytics script tags. Those tags are inert text inside a snapshot; nothing
in this repository executes or serves them.

### 2.3 Per-file manifest

| Snapshot file | Licence | Bytes |
|---|---|---:|
| `drupal-api-11/ec8e40e7befc5c53f78a56c92db98e9baff0f726032d845bd881e29802c2e818.txt` | GPL-2.0-or-later | 1,124 |
| `drupal-apis-guide/644a9dd934245480ebd33f0c67ad4af0ecfa16db0dab5a90dffb0915fd5e3dfb.txt` | CC-BY-SA-2.0 | 7,624 |
| `drupal-core-releases/2c6302dcfe0d2dd98afb22db753b6ee0761b9440555b71b1af2272b9ba84c2fb.txt` | CC-BY-SA-2.0 | 543,079 |
| `drupal-core-releases/c7de75d2508c7d134765affdea101e9bc7a4d534d8eaaa97fda3308a14ea0063.txt` | CC-BY-SA-2.0 | 540,265 |
| `drupal-core-change-record-policy/c205ef0431be72f5d5564b6383fbd6fc46793aebdc8268741bd666d99bf79152.txt` | CC-BY-SA-2.0 | 2,795 |
| `drupal-core-change-records/5603068ca984c70c41111c670a82d1dda53d07d1a1dc11bb30280d80b901e514.txt` | CC-BY-SA-2.0 | 4,703 |
| `drupal-core-change-records/e554ba391a792676cc84cc4a7c58da270b2320d5007b2cfa453420575526fefb.txt` | CC-BY-SA-2.0 | 4,649 |
| `drupal-security-core/bac9a6c286e56a5c6e66cbeba200e3400fe73fcb5c2d9d5b98e60dd431891c8e.txt` | CC-BY-SA-2.0 | 6,760 |
| `drupal-security-contrib/eb46379ccc9af6cdebafdca523d0e6a8158754aed8c8d1b15275c52c095e534e.txt` | CC-BY-SA-2.0 | 7,409 |
| `drupal-security-contrib/f389ae0c83baf3301c9f9a1673800cd36ba7d5c687f96a4783ee14263f494d11.txt` | CC-BY-SA-2.0 | 6,541 |
| `drupal-security-psa/325d64eb555d4c3bd2d724c22b4b954b45c4328c7e34807d1054d40a7f18ecff.txt` | CC-BY-SA-2.0 | 5,421 |
| `drupal-secure-code/f57c9014ebb02fdef09c649f4d56e7645a727d5075034cd13e19d1f92d7c31a8.txt` | CC-BY-SA-2.0 | 5,603 |
| `drupal-coding-standards-project/9ec69ae06e588174fe2367f679ca1f12e2321c6411dd02c0b9968f058feb4862.txt` | CC-BY-SA-2.0 | 3,085 |
| `drupal-coding-standards-current/2e58cdd9d0b1642b5a461970d2386bacb187b1621aeadf1db62309b5ca85045b.txt` | GPL-2.0-or-later | 653 |
| `drupal-coding-standards-change-records/b7bf0a88582c743acdfe3d10335a0a08211a923715144bce3d5f9bc0fc16b607.txt` | CC-BY-SA-2.0 | 972 |
| `drupal-update-project-release-semantics/5ceb699008f74d539aaabed9e02c560071f1d90508023cb1f11735002357cd45.txt` | GPL-2.0-or-later | 6,972 |
| `drupal-update-status-security-semantics/8d7431ff04ac7d80d830e60f0dbc8fbfd24ac36c0e16d9966c2ed74782726546.txt` | GPL-2.0-or-later | 23,273 |
| `drupal-update-manager-interface-semantics/5076c3ad1871e97b198e7dda5caf20084cf4514403025ea751153ab212b879eb.txt` | GPL-2.0-or-later | 4,814 |
| `drupal-contrib-token-releases/271ad3567d24b6f4398cbbf1201e2dfabba2b93e296b8b52df41628a13230219.txt` | CC-BY-SA-2.0 | 24,195 |
| `drupal-contrib-pathauto-releases/f887eea8671621502c2fb9f590f2866df2a41facff686ca016d60fa2d7984985.txt` | CC-BY-SA-2.0 | 25,638 |
| `drupal-security-advisories-core/2416cd08628ca6f8dd5dd873feae9ac23bc4bb709630ef87a5430f737c202dc4.txt` | CC-BY-SA-2.0 | 154,005 |
| `drupal-security-advisories-recent/ff1e03172279c4ad58d96b45feece3b2d2c931ce6fcb91d975855104b074683c.txt` | CC-BY-SA-2.0 | 82,719 |
| `drupal-upgrade-process-overview/82c4fc596dbd7339b25a5c21f7d8c50a6288a7d1adff8017784055790d8a5410.txt` | CC-BY-SA-2.0 | 2,439 |
| `drupal-upgrade-9-to-10/890acda19673beebea7c6b38b96b39abe3eb07f06dced789474101f07debef0c.txt` | CC-BY-SA-2.0 | 11,408 |
| `drupal-upgrade-10-to-11/caed10fd7ac71226b75e303b3641b1f5dbfde95c7705e8f13613827631dc2578.txt` | CC-BY-SA-2.0 | 6,736 |
| `drupal-upgrade-11-to-12/9138db90ff9288c683ef29d6be46c5e611fddf3fdde519b81449fce5604e5ac2.txt` | CC-BY-SA-2.0 | 4,916 |
| `drupal-php-requirements/2b19eb6eb8d32ef430bd6227142cfaf54e631ab5d707ac2cdb98403ecdd58e21.txt` | CC-BY-SA-2.0 | 8,533 |
| `drupal-api-deprecated-9-p0/a907598611296099dcb871b719b4476321e94d21c0defa1f45aa4166c2e99607.txt` | GPL-2.0-or-later | 84,950 |
| `drupal-api-deprecated-9-p1/b4732697f35f5875305eb01427b753d902c47e297f9f741e905d52e8f83decb8.txt` | GPL-2.0-or-later | 83,376 |
| `drupal-api-deprecated-9-p2/9b9b29988d9a578f1c1aa42e199468eb01c48ec4d1f47e0d04720e494547288c.txt` | GPL-2.0-or-later | 80,452 |
| `drupal-api-deprecated-9-p3/322ca48f208aaa048e06628a58371515c74386c9079123679eecd1687e8a477f.txt` | GPL-2.0-or-later | 82,298 |
| `drupal-api-deprecated-9-p4/5a0d6b64ef0272324ee322b307b2c253a4b5a5ea16805c937bd9c56b12d3c75d.txt` | GPL-2.0-or-later | 58,250 |
| `drupal-core-change-notices/2f00fe48197087de210c09af8fd203f08a62d338889e68875b69ee621bcf44eb.txt` | CC-BY-SA-2.0 | 73,477 |
| `drupal-trusted-host-settings/11e4f4be0c3b46177c5f8fa6ad0fa7d76bba3fd08f61d9b06252b930b0f7f407.txt` | CC-BY-SA-2.0 | 10,027 |
| `drupal-internal-page-cache/46b0c8959410ff7f48b88216fd8ddeb4a0d794b1ced02919c1707b8048663b68.txt` | CC-BY-SA-2.0 | 3,903 |
| `drupal-cache-tags/35e950799ef519216d7b7f02340a70dae591c29214e9421543051df38762989b.txt` | CC-BY-SA-2.0 | 9,711 |
| `drupal-default-settings-php/1e2df3981d9cc138fa916171a710909b3e6922ebd978252b453b903e540b4a39.txt` | GPL-2.0-or-later | 35,879 |

## 3. Derived structured records

`security/advisories/`, `api/lifecycle/` and `api/change-records/` are
generated by the engines from the snapshots above. They carry structured
facts (identifiers, versions, dates, URLs) plus short quoted excerpts — an
advisory title, a `@deprecated` annotation, a change-record excerpt — and
every record names its `canonical_url` or `source_url` and snapshot hash.
The quoted text remains CC-BY-SA-2.0 (Drupal.org content) or
GPL-2.0-or-later (api.drupal.org / core annotations) material with
attribution; the record structure and the engine's own fields are original
Apache-2.0 work.

## 4. Reviewed records that quote sources

`rules/implementation/`, `knowledge/context/` and some `knowledge/records/`
quote the lines of a snapshot they were reviewed against. Those quotations
are attributed by source id and snapshot hash in the record itself and remain
under the source's terms; the review, structure and conclusions are original.

## 5. Drupal-derived code

No Drupal module, theme or library is vendored. The only Drupal core code in
the repository is inside snapshots: `drupal-default-settings-php`
(`sites/default/default.settings.php` as served by api.drupal.org) and the
three `drupal-update-*-semantics` families (core `update` module source
fetched verbatim from the core Git repository at tag 11.4.5). They are
GPL-2.0-or-later, carry Drupal core's whole-work copyright notice (E4) by
reference, and are stored as provenance for reviewed rules, never executed,
imported or modified.

## 6. Third-party libraries

None. The dependency policy is the Python standard library only, proven at
every validation by the import scan in `scripts/dk_release_meta.py` and
`scripts/test_supply_chain_security.py`; `release/sbom.json` lists zero
third-party Python dependencies. The website loads no external script,
stylesheet or font.

## 7. Test fixtures

`tests/fixtures/` is synthetic. Fixture `composer.json` / `composer.lock`
files name real Drupal packages and versions (facts) but contain no copied
project code beyond a few placeholder lines written for the tests. The one
solved-case fixture (`tests/fixtures/solved-case/`) and the solved case
captured from it (`cases/solved/`) are test-derived: they describe a tooling
defect in generic terms, carry fingerprints only, and contain no third-party
text.

## 8. Images and other assets

The repository ships no images, no fonts and no logos — in particular no
Drupal logo, Druplicon or other protected branding (see `TRADEMARK.md`).
`public-site/assets/` holds an original stylesheet and an original search
script.

## 9. Unresolved items

None at this release. If you believe material in this repository is
redistributed in a way its licence does not permit, open an issue or use the
disclosure path in `SECURITY.md`; the maintainers will remove or replace it.
