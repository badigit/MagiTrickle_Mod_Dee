import { IntervalTree } from "../../utils/interval-tree";
import { IPUtils } from "../../utils/ip";
import type { Group } from "../../types";
import type { GroupsStore } from "../groups/groups.svelte";

export const CONFLICTS_STORE_CONTEXT = Symbol("conflicts-store");

export type ConflictPair = {
  groupAIndex: number;
  groupAId: string;
  ruleAIndex: number;
  ruleAId: string;
  ruleAName: string;
  ruleAType: string;
  groupAName: string;
  patternA: string;
  groupBIndex: number;
  groupBId: string;
  ruleBIndex: number;
  ruleBId: string;
  ruleBName: string;
  ruleBType: string;
  groupBName: string;
  patternB: string;
};

type RuleRef = {
  groupIndex: number;
  groupId: string;
  ruleIndex: number;
  ruleId: string;
  ruleType: string;
  ruleName: string;
  groupName: string;
  pattern: string;
};

function normalizeCIDR(cidr: string, isIPv6: boolean): string {
  if (cidr.includes("/")) return cidr;
  return `${cidr}/${isIPv6 ? 128 : 32}`;
}

/** Returns true if `pattern` is covered by `namespace` (exact or subdomain). */
function isSubsumedBy(namespace: string, pattern: string): boolean {
  const ns = namespace.toLowerCase();
  const p = pattern.toLowerCase();
  return p === ns || p.endsWith("." + ns);
}

function makePair(a: RuleRef, b: RuleRef): ConflictPair {
  return {
    groupAIndex: a.groupIndex,
    groupAId: a.groupId,
    ruleAIndex: a.ruleIndex,
    ruleAId: a.ruleId,
    ruleAName: a.ruleName,
    ruleAType: a.ruleType,
    groupAName: a.groupName,
    patternA: a.pattern,
    groupBIndex: b.groupIndex,
    groupBId: b.groupId,
    ruleBIndex: b.ruleIndex,
    ruleBId: b.ruleId,
    ruleBName: b.ruleName,
    ruleBType: b.ruleType,
    groupBName: b.groupName,
    patternB: b.pattern,
  };
}

const DOMAIN_TYPES = new Set(["domain", "namespace", "wildcard"]);

export class ConflictsStore {
  #dispose: (() => void) | null = null;

  conflicts = $state<ConflictPair[]>([]);

  conflictsByRuleId = $derived.by(() => {
    const map = new Map<string, ConflictPair[]>();
    for (const c of this.conflicts) {
      if (!map.has(c.ruleAId)) map.set(c.ruleAId, []);
      map.get(c.ruleAId)!.push(c);
      if (!map.has(c.ruleBId)) map.set(c.ruleBId, []);
      map.get(c.ruleBId)!.push(c);
    }
    return map;
  });

  groupsWithConflicts = $derived.by(() => {
    const set = new Set<number>();
    for (const c of this.conflicts) {
      set.add(c.groupAIndex);
      set.add(c.groupBIndex);
    }
    return set;
  });

  conflictCountByGroup = $derived.by(() => {
    const map = new Map<number, number>();
    for (const c of this.conflicts) {
      map.set(c.groupAIndex, (map.get(c.groupAIndex) ?? 0) + 1);
      if (c.groupBIndex !== c.groupAIndex) {
        map.set(c.groupBIndex, (map.get(c.groupBIndex) ?? 0) + 1);
      }
    }
    return map;
  });

  hasConflicts = $derived(this.conflicts.length > 0);
  count = $derived(this.conflicts.length);

  constructor(private groupsStore: GroupsStore) {
    this.#dispose = $effect.root(() => {
      $effect(() => {
        void this.groupsStore.dataRevision;
        void this.groupsStore.data; // track initial load (dataRevision stays 0 on mount)
        this.#compute();
      });
    });
  }

  destroy() {
    if (this.#dispose) {
      this.#dispose();
      this.#dispose = null;
    }
  }

  navigateToRule(groupId: string, ruleId: string) {
    this.groupsStore.open_state[groupId] = true;
    requestAnimationFrame(() => {
      const el = document.querySelector<HTMLElement>(`.rule[data-uuid="${ruleId}"]`);
      if (!el) return;
      el.scrollIntoView({ behavior: "smooth", block: "center" });
      el.classList.add("conflict-highlight");
      setTimeout(() => el.classList.remove("conflict-highlight"), 1500);
    });
  }

  #compute() {
    const groups = this.groupsStore.data as Group[];
    const conflicts: ConflictPair[] = [];
    const ipv4Rules: RuleRef[] = [];
    const ipv6Rules: RuleRef[] = [];
    const domainRules: RuleRef[] = [];

    for (let gi = 0; gi < groups.length; gi++) {
      const group = groups[gi];
      for (let ri = 0; ri < group.rules.length; ri++) {
        const rule = group.rules[ri];
        if (!rule.rule || !rule.enable) continue;

        const base = {
          groupIndex: gi,
          groupId: group.id,
          ruleIndex: ri,
          ruleId: rule.id,
          ruleType: rule.type,
          ruleName: rule.name,
          groupName: group.name,
        };

        if (rule.type === "subnet") {
          ipv4Rules.push({ ...base, pattern: normalizeCIDR(rule.rule, false) });
        } else if (rule.type === "subnet6") {
          ipv6Rules.push({ ...base, pattern: normalizeCIDR(rule.rule, true) });
        } else if (DOMAIN_TYPES.has(rule.type)) {
          domainRules.push({ ...base, pattern: rule.rule.toLowerCase() });
        }
      }
    }

    this.#findSubnetConflicts(ipv4Rules, false, conflicts);
    this.#findSubnetConflicts(ipv6Rules, true, conflicts);
    this.#findDomainConflicts(domainRules, conflicts);

    this.conflicts = conflicts;
  }

  #findSubnetConflicts(rules: RuleRef[], isIPv6: boolean, out: ConflictPair[]) {
    if (rules.length < 2) return;

    const tree = new IntervalTree<RuleRef>();

    for (const rule of rules) {
      const parsed = IPUtils.parseCIDR(rule.pattern);
      if (!parsed) continue;
      if (isIPv6) {
        const range = IPUtils.getIPv6Range(parsed);
        if (range) tree.insert(range.start, range.end, rule);
      } else {
        const range = IPUtils.getIPv4Range(parsed);
        if (range) tree.insert(range.start, range.end, rule);
      }
    }

    tree.build();

    const seen = new Set<string>();

    for (const rule of rules) {
      const parsed = IPUtils.parseCIDR(rule.pattern);
      if (!parsed) continue;

      let matches: RuleRef[];
      if (isIPv6) {
        const range = IPUtils.getIPv6Range(parsed);
        if (!range) continue;
        matches = tree.query(range.start, range.end);
      } else {
        const range = IPUtils.getIPv4Range(parsed);
        if (!range) continue;
        matches = tree.query(range.start, range.end);
      }

      for (const match of matches) {
        if (match.ruleId === rule.ruleId) continue;
        const key = [rule.ruleId, match.ruleId].sort().join(":");
        if (seen.has(key)) continue;
        seen.add(key);
        out.push(makePair(rule, match));
      }
    }
  }

  #findDomainConflicts(rules: RuleRef[], out: ConflictPair[]) {
    if (rules.length < 2) return;

    const seen = new Set<string>();

    for (let i = 0; i < rules.length; i++) {
      for (let j = i + 1; j < rules.length; j++) {
        const a = rules[i];
        const b = rules[j];

        const key = [a.ruleId, b.ruleId].sort().join(":");
        if (seen.has(key)) continue;

        let conflict = false;

        // Exact duplicate (same type + same pattern)
        if (a.ruleType === b.ruleType && a.pattern === b.pattern) {
          conflict = true;
        }

        // namespace subsumes domain or namespace
        if (!conflict && a.ruleType === "namespace" && (b.ruleType === "domain" || b.ruleType === "namespace")) {
          if (isSubsumedBy(a.pattern, b.pattern)) conflict = true;
        }
        if (!conflict && b.ruleType === "namespace" && (a.ruleType === "domain" || a.ruleType === "namespace")) {
          if (isSubsumedBy(b.pattern, a.pattern)) conflict = true;
        }

        if (conflict) {
          seen.add(key);
          out.push(makePair(a, b));
        }
      }
    }
  }
}
