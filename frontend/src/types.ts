export interface Rule {
  rule_type: string;
  value: string;
}

export interface RulesetSummary {
  name: string;
  slug: string;
  rule_count: number;
  url: string;
  protected: boolean;
}

export interface RulesetDetail {
  name: string;
  slug: string;
  read_key?: string;
  protected: boolean;
  url: string;
  rules: Rule[];
}