import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Copy, Languages, LogOut, Plus, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from '@/components/ui/alert-dialog';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from '@/components/ui/empty';
import { Field, FieldContent, FieldDescription, FieldGroup, FieldLabel } from '@/components/ui/field';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import { Switch } from '@/components/ui/switch';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import {
  ApiError,
  RULE_TYPES,
  addRule,
  createRuleset,
  deleteRule,
  deleteRuleset,
  fullPublicUrl,
  getRuleset,
  getToken,
  listRulesets,
  setToken,
  updateRuleset,
} from './api';
import type { Rule, RulesetDetail, RulesetSummary } from './types';

function App() {
  const { t, i18n } = useTranslation();
  const [hasToken, setHasToken] = useState<boolean>(() => getToken() !== '');
  const [tokenInput, setTokenInput] = useState('');
  const [rulesets, setRulesets] = useState<RulesetSummary[]>([]);
  const [selected, setSelected] = useState<RulesetDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);

  // New ruleset form
  const [newName, setNewName] = useState('');
  const [newSlug, setNewSlug] = useState('');

  // Add-rule form
  const [ruleType, setRuleType] = useState(RULE_TYPES[0]);
  const [ruleValue, setRuleValue] = useState('');

  const toggleLanguage = () => {
    void i18n.changeLanguage(i18n.language === 'zh' ? 'en' : 'zh');
  };

  const handleError = useCallback((err: unknown) => {
    if (err instanceof ApiError && err.status === 401) {
      setHasToken(false);
      setSelected(null);
      setRulesets([]);
      toast.error(t('auth.expired'));
      return;
    }
    toast.error(err instanceof Error ? err.message : String(err));
  }, [t]);

  const refresh = useCallback(async () => {
    try {
      setRulesets(await listRulesets());
    } catch (err) {
      handleError(err);
    } finally {
      setLoading(false);
    }
  }, [handleError]);

  useEffect(() => {
    if (hasToken) {
      void refresh();
    } else {
      setLoading(false);
    }
  }, [hasToken, refresh]);

  const selectRuleset = useCallback(
    async (slug: string) => {
      setDetailLoading(true);
      try {
        setSelected(await getRuleset(slug));
      } catch (err) {
        handleError(err);
      } finally {
        setDetailLoading(false);
      }
    },
    [handleError],
  );

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    const token = tokenInput.trim();
    if (!token) {
      toast.error(t('login.tokenRequired'));
      return;
    }
    setToken(token);
    setHasToken(true);
    setTokenInput('');
  };

  const handleLogout = () => {
    setToken('');
    setHasToken(false);
    setSelected(null);
    setRulesets([]);
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    const name = newName.trim();
    if (!name) {
      toast.error(t('create.nameRequired'));
      return;
    }
    try {
      const created = await createRuleset(name, newSlug.trim() || undefined);
      setNewName('');
      setNewSlug('');
      await refresh();
      await selectRuleset(created.slug);
      toast.success(t('create.success', { name: created.name }));
    } catch (err) {
      handleError(err);
    }
  };

  const handleDeleteRuleset = async (slug: string, name: string) => {
    try {
      await deleteRuleset(slug);
      setSelected((prev) => (prev?.slug === slug ? null : prev));
      await refresh();
      toast.success(t('list.deleted', { name }));
    } catch (err) {
      handleError(err);
    }
  };

  const handleRename = async (name: string) => {
    if (!selected) return;
    const trimmed = name.trim();
    if (!trimmed || trimmed === selected.name) return;
    try {
      const detail = await updateRuleset(selected.slug, { name: trimmed });
      setSelected(detail);
      await refresh();
      toast.success(t('detail.nameUpdated'));
    } catch (err) {
      handleError(err);
    }
  };

  const handleToggleProtected = async (requireKey: boolean) => {
    if (!selected) return;
    try {
      const detail = await updateRuleset(selected.slug, { require_key: requireKey });
      setSelected(detail);
      toast.success(requireKey ? t('detail.protectOn') : t('detail.protectOff'));
    } catch (err) {
      handleError(err);
    }
  };

  const handleCopyUrl = async () => {
    if (!selected) return;
    const url = fullPublicUrl(selected);
    try {
      await navigator.clipboard.writeText(url);
      toast.success(t('detail.urlCopied'));
    } catch {
      toast.error(t('detail.copyFailed'));
    }
  };

  const handleAddRule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selected) return;
    const value = ruleValue.trim();
    if (!value) {
      toast.error(t('detail.valueRequired'));
      return;
    }
    try {
      await addRule(selected.slug, { rule_type: ruleType, value });
      setRuleValue('');
      const detail = await getRuleset(selected.slug);
      setSelected(detail);
      await refresh();
      toast.success(t('detail.ruleAdded'));
    } catch (err) {
      handleError(err);
    }
  };

  const handleDeleteRule = async (rule: Rule) => {
    if (!selected) return;
    try {
      await deleteRule(selected.slug, rule);
      const detail = await getRuleset(selected.slug);
      setSelected(detail);
      await refresh();
      toast.success(t('detail.ruleDeleted'));
    } catch (err) {
      handleError(err);
    }
  };

  // ---- Sign-in page ----
  if (!hasToken) {
    return (
      <div className="flex min-h-screen items-center justify-center p-4">
        <Card className="w-full max-w-sm">
          <CardHeader>
            <CardTitle className="text-xl">{t('app.title')}</CardTitle>
            <CardDescription>{t('login.description')}</CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleLogin}>
              <FieldGroup>
                <Field>
                  <FieldLabel htmlFor="token">{t('login.token')}</FieldLabel>
                  <FieldContent>
                    <Input
                      id="token"
                      type="password"
                      placeholder={t('login.tokenPlaceholder')}
                      value={tokenInput}
                      onChange={(e) => setTokenInput(e.target.value)}
                      autoFocus
                      autoComplete="current-password"
                    />
                  </FieldContent>
                </Field>
              </FieldGroup>
              <Button type="submit" className="mt-4 w-full">
                {t('login.signIn')}
              </Button>
            </form>
          </CardContent>
        </Card>
      </div>
    );
  }

  // ---- Main UI ----
  return (
    <div className="flex min-h-screen flex-col bg-background text-foreground">
      <header className="sticky top-0 z-10 flex h-14 items-center justify-between border-b bg-background/95 px-4 backdrop-blur">
        <h1 className="text-lg font-semibold">{t('app.title')}</h1>
        <div className="flex items-center gap-3">
          <span className="text-sm text-muted-foreground">
            {t('topbar.tokenConfigured', { count: getToken().length })}
          </span>
          <Button variant="ghost" size="sm" onClick={toggleLanguage}>
            <Languages data-icon="inline-start" />
            {i18n.language === 'zh' ? 'EN' : '中文'}
          </Button>
          <Button variant="ghost" size="sm" onClick={handleLogout}>
            <LogOut data-icon="inline-start" />
            {t('topbar.signOut')}
          </Button>
        </div>
      </header>

      <div className="flex flex-1 flex-col gap-4 p-4 lg:flex-row">
        {/* Left: ruleset list */}
        <aside className="flex w-full shrink-0 flex-col gap-4 lg:w-80">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">{t('create.title')}</CardTitle>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleCreate} className="flex flex-col gap-3">
                <FieldGroup>
                  <Field>
                    <FieldLabel htmlFor="new-name">{t('create.name')}</FieldLabel>
                    <FieldContent>
                      <Input
                        id="new-name"
                        placeholder={t('create.namePlaceholder')}
                        value={newName}
                        onChange={(e) => setNewName(e.target.value)}
                      />
                    </FieldContent>
                  </Field>
                  <Field>
                    <FieldLabel htmlFor="new-slug">{t('create.slug')}</FieldLabel>
                    <FieldContent>
                      <Input
                        id="new-slug"
                        placeholder={t('create.slugPlaceholder')}
                        value={newSlug}
                        onChange={(e) => setNewSlug(e.target.value)}
                      />
                      <FieldDescription>{t('create.slugHint')}</FieldDescription>
                    </FieldContent>
                  </Field>
                </FieldGroup>
                <Button type="submit" className="w-full">
                  <Plus data-icon="inline-start" />
                  {t('create.submit')}
                </Button>
              </form>
            </CardContent>
          </Card>

          {loading ? (
            <div className="flex flex-col gap-2">
              <Skeleton className="h-16 w-full" />
              <Skeleton className="h-16 w-full" />
              <Skeleton className="h-16 w-full" />
            </div>
          ) : rulesets.length === 0 ? (
            <Card>
              <CardContent>
                <Empty>
                  <EmptyHeader>
                    <EmptyTitle>{t('list.emptyTitle')}</EmptyTitle>
                  </EmptyHeader>
                  <EmptyDescription>{t('list.emptyDescription')}</EmptyDescription>
                </Empty>
              </CardContent>
            </Card>
          ) : (
            <div className="flex flex-col gap-2">
              {rulesets.map((rs) => (
                <Card
                  key={rs.slug}
                  className={selected?.slug === rs.slug ? 'border-primary ring-1 ring-primary' : ''}
                >
                  <div className="flex items-stretch">
                    <Button
                      variant="ghost"
                      className="h-auto flex-1 items-start justify-start gap-1.5 rounded-none px-4 py-3 text-left"
                      onClick={() => void selectRuleset(rs.slug)}
                    >
                      <span className="flex w-full flex-col gap-1">
                        <span className="text-sm font-semibold">{rs.name}</span>
                        <span className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                          {t('list.rulesCount', { count: rs.rule_count })} · /r/{rs.slug}
                        </span>
                      </span>
                    </Button>
                    <AlertDialog>
                      <AlertDialogTrigger asChild>
                        <Button
                          variant="ghost"
                          size="icon"
                          aria-label={t('list.deleteAria', { name: rs.name })}
                          className="self-center text-muted-foreground hover:text-destructive"
                        >
                          <Trash2 />
                        </Button>
                      </AlertDialogTrigger>
                      <AlertDialogContent>
                        <AlertDialogHeader>
                          <AlertDialogTitle>{t('list.deleteTitle')}</AlertDialogTitle>
                          <AlertDialogDescription>
                            {t('list.deleteDescription', { name: rs.name })}
                          </AlertDialogDescription>
                        </AlertDialogHeader>
                        <AlertDialogFooter>
                          <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
                          <AlertDialogAction
                            onClick={() => void handleDeleteRuleset(rs.slug, rs.name)}
                          >
                            {t('common.delete')}
                          </AlertDialogAction>
                        </AlertDialogFooter>
                      </AlertDialogContent>
                    </AlertDialog>
                  </div>
                </Card>
              ))}
            </div>
          )}
        </aside>

        {/* Right: ruleset detail */}
        <main className="min-w-0 flex-1">
          {!selected ? (
            <Card>
              <CardContent>
                <Empty>
                  <EmptyHeader>
                    <EmptyTitle>{t('detail.noneTitle')}</EmptyTitle>
                  </EmptyHeader>
                  <EmptyDescription>{t('detail.noneDescription')}</EmptyDescription>
                </Empty>
              </CardContent>
            </Card>
          ) : detailLoading ? (
            <div className="flex flex-col gap-4">
              <Skeleton className="h-24 w-full" />
              <Skeleton className="h-48 w-full" />
            </div>
          ) : (
            <div className="flex flex-col gap-4">
              <Card>
                <CardHeader>
                  <div className="flex flex-col gap-3">
                    <Input
                      className="h-9 text-base font-semibold"
                      defaultValue={selected.name}
                      key={selected.slug + selected.name}
                      onBlur={(e) => void handleRename(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') (e.target as HTMLInputElement).blur();
                      }}
                    />
                    <div className="flex items-center gap-2">
                      <Switch
                        id="require-key"
                        checked={selected.protected}
                        onCheckedChange={(checked) => void handleToggleProtected(checked)}
                      />
                      <label htmlFor="require-key" className="text-sm text-muted-foreground">
                        {t('detail.requireKey')}
                      </label>
                      {selected.protected && <Badge variant="secondary">{t('detail.protected')}</Badge>}
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="flex flex-col gap-2">
                    <div className="flex gap-2">
                      <Input
                        className="font-mono text-xs"
                        readOnly
                        value={fullPublicUrl(selected)}
                        onFocus={(e) => e.target.select()}
                      />
                      <Button onClick={() => void handleCopyUrl()}>
                        <Copy data-icon="inline-start" />
                        {t('detail.copyUrl')}
                      </Button>
                    </div>
                    <p className="text-sm text-muted-foreground">{t('detail.urlHint')}</p>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-base">
                    {t('detail.rulesTitle', { count: selected.rules.length })}
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {selected.rules.length === 0 ? (
                    <Empty>
                      <EmptyHeader>
                        <EmptyTitle>{t('detail.noRules')}</EmptyTitle>
                      </EmptyHeader>
                      <EmptyDescription>{t('detail.addFirstRule')}</EmptyDescription>
                    </Empty>
                  ) : (
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead className="w-44">{t('detail.type')}</TableHead>
                          <TableHead>{t('detail.value')}</TableHead>
                          <TableHead className="w-20 text-right">{t('detail.actions')}</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {selected.rules.map((rule, i) => (
                          <TableRow key={`${rule.rule_type}-${rule.value}-${i}`}>
                            <TableCell>
                              <Badge variant="outline" className="font-mono text-xs">
                                {rule.rule_type}
                              </Badge>
                            </TableCell>
                            <TableCell className="break-all font-mono text-xs">
                              {rule.value}
                            </TableCell>
                            <TableCell className="text-right">
                              <Button
                                variant="ghost"
                                size="sm"
                                className="text-muted-foreground hover:text-destructive"
                                onClick={() => void handleDeleteRule(rule)}
                              >
                                <Trash2 data-icon="inline-start" />
                                {t('common.delete')}
                              </Button>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  )}

                  <form onSubmit={handleAddRule} className="mt-4 flex flex-col gap-2 sm:flex-row">
                    <Select value={ruleType} onValueChange={setRuleType}>
                      <SelectTrigger className="sm:w-56">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {RULE_TYPES.map((type) => (
                          <SelectItem key={type} value={type}>
                            {type}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <Input
                      className="flex-1"
                      placeholder={t('detail.valuePlaceholder')}
                      value={ruleValue}
                      onChange={(e) => setRuleValue(e.target.value)}
                    />
                    <Button type="submit">
                      <Plus data-icon="inline-start" />
                      {t('detail.addRule')}
                    </Button>
                  </form>
                </CardContent>
              </Card>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

export default App;
