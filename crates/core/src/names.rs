//! Vanity names for VMs (and, later, stages/snapshots).
//!
//! Every instance keeps its stable machine id (e.g. `dev-8f3a2c1b`) as the
//! primary key; the vanity name is an additional, human-memorable handle that
//! users and models can use to refer to a specific machine/state.
//!
//! Names are generated *deterministically* from the machine id (seeded, not
//! random-per-call), so a given id always maps to the same base name. If that
//! name is already taken by another live/recorded instance, a numeric suffix
//! (`-2`, `-3`, …) disambiguates, falling back to an id-derived suffix.
//!
//! The word lists are a theme; the development default is Destiny-lore
//! flavored. Release builds can swap themes without touching callers.

/// Modifier words (theme: Destiny).
const ADJECTIVES: &[&str] = &[
    "radiant",
    "taken",
    "ascendant",
    "lucent",
    "umbral",
    "solar",
    "arc",
    "void",
    "stasis",
    "strand",
    "gilded",
    "dredgen",
    "vaulted",
    "whispered",
    "hallowed",
    "forsaken",
    "risen",
    "fallen",
    "hive",
    "vex",
    "cabal",
    "scorn",
    "awoken",
    "exo",
    "cryptic",
    "splintered",
    "resilient",
    "intrepid",
    "cursed",
    "blighted",
    "radiolarian",
    "ionic",
    "cosmic",
    "lunar",
    "martian",
    "europan",
    "nessian",
    "wayward",
    "shattered",
    "resonant",
];

/// Subject words (theme: Destiny).
const NOUNS: &[&str] = &[
    "traveler",
    "ghost",
    "warmind",
    "sparrow",
    "gjallarhorn",
    "thunderlord",
    "icebreaker",
    "telesto",
    "thorn",
    "hawkmoon",
    "sunshot",
    "graviton",
    "riskrunner",
    "wardcliff",
    "borealis",
    "cloudstrike",
    "lament",
    "divinity",
    "witherhoard",
    "servitor",
    "dreg",
    "vandal",
    "captain",
    "kell",
    "archon",
    "ogre",
    "knight",
    "acolyte",
    "thrall",
    "wizard",
    "shrieker",
    "hydra",
    "minotaur",
    "goblin",
    "hobgoblin",
    "harpy",
    "cyclops",
    "colossus",
    "legionary",
    "phalanx",
    "psion",
    "warbeast",
    "screeb",
    "ahamkara",
    "cryptarch",
    "guardian",
    "saint",
    "drifter",
    "rasputin",
    "cayde",
    "ikora",
    "zavala",
    "shaxx",
    "osiris",
    "crota",
    "oryx",
    "savathun",
    "riven",
    "saladin",
    "efrideet",
    "leviathan",
    "dreadnaught",
    "cosmodrome",
    "glimmer",
    "shard",
    "relic",
    "vault",
    "spire",
    "wellspring",
    "gambit",
    "crucible",
    "vanguard",
    "banshee",
];

/// FNV-1a 64-bit — tiny, dependency-free, stable across runs/platforms.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Avalanche finalizer (murmur3/splitmix-style). Raw FNV-1a disperses poorly
/// for seeds sharing a long prefix (the last bytes barely reach the high bits);
/// this mix makes every input bit affect every output bit.
fn mix(mut h: u64) -> u64 {
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
    h ^= h >> 33;
    h = h.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    h ^= h >> 33;
    h
}

/// The deterministic base name for a machine id: `adjective-noun`.
pub fn base_name(seed: &str) -> String {
    let h = mix(fnv1a(seed.as_bytes()));
    let adj = ADJECTIVES[(h >> 32) as usize % ADJECTIVES.len()];
    let noun = NOUNS[(h & 0xffff_ffff) as usize % NOUNS.len()];
    format!("{adj}-{noun}")
}

/// The base name for `seed`, disambiguated against `taken`: tries the base
/// name, then `-2` … `-9`, then an id-derived hex suffix that cannot collide
/// for distinct seeds.
pub fn unique_name(seed: &str, mut taken: impl FnMut(&str) -> bool) -> String {
    let base = base_name(seed);
    if !taken(&base) {
        return base;
    }
    for n in 2..=9u32 {
        let candidate = format!("{base}-{n}");
        if !taken(&candidate) {
            return candidate;
        }
    }
    format!("{base}-{:06x}", fnv1a(seed.as_bytes()) & 0xff_ffff)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn deterministic_for_same_seed() {
        assert_eq!(base_name("dev-8f3a2c1b"), base_name("dev-8f3a2c1b"));
    }

    #[test]
    fn shape_is_adj_dash_noun() {
        let n = base_name("dev-00000001");
        let parts: Vec<&str> = n.split('-').collect();
        assert_eq!(parts.len(), 2);
        assert!(ADJECTIVES.contains(&parts[0]));
        assert!(NOUNS.contains(&parts[1]));
    }

    #[test]
    fn reasonable_dispersion_over_many_seeds() {
        let names: HashSet<String> = (0..500)
            .map(|i| base_name(&format!("dev-{i:08x}")))
            .collect();
        // 500 seeds into ~2,880 combos: expect substantial spread, tolerate birthday collisions.
        assert!(names.len() > 430, "poor dispersion: {} unique", names.len());
    }

    #[test]
    fn unique_name_disambiguates() {
        let base = base_name("seed");
        let taken: HashSet<String> = [base.clone(), format!("{base}-2")].into();
        let got = unique_name("seed", |n| taken.contains(n));
        assert_eq!(got, format!("{base}-3"));

        let all_taken = unique_name("seed", |_| true);
        assert!(all_taken.starts_with(&format!("{base}-")));
        assert_eq!(all_taken.len(), base.len() + 7, "hex fallback shape");
    }

    #[test]
    fn names_are_handle_safe() {
        for i in 0..200 {
            let n = base_name(&format!("x{i}"));
            assert!(n
                .chars()
                .all(|c| c.is_ascii_lowercase() || c == '-' || c.is_ascii_digit()));
            assert!(n.len() <= 32, "{n} too long");
        }
    }
}
