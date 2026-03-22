import hashlib
import json
import os
import sqlite3
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from shutil import which
from typing import Optional
from urllib.parse import urlparse

try:
    import tomllib  # py311+
except Exception:
    import tomli as tomllib

import requests
from playwright.sync_api import sync_playwright


def load_config(path: str):
    with open(path, 'rb') as f:
        return tomllib.load(f)


def ensure_parent(path: str):
    Path(path).parent.mkdir(parents=True, exist_ok=True)


def save_json(path: str, data: dict):
    ensure_parent(path)
    Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def read_json(path: str):
    p = Path(path)
    if not p.exists():
        return None
    return json.loads(p.read_text('utf-8'))


def chrome_running(port: int) -> bool:
    try:
        r = requests.get(f'http://127.0.0.1:{port}/json/version', timeout=3)
        return r.ok
    except Exception:
        return False


def chrome_version(port: int):
    try:
        r = requests.get(f'http://127.0.0.1:{port}/json/version', timeout=3)
        if not r.ok:
            return None
        return r.json()
    except Exception:
        return None


def _token_looks_like_url(token: str) -> bool:
    token = (token or '').strip().lower()
    return token.startswith('http://') or token.startswith('https://') or '/api/plugin/update-token' in token


def health_report(cfg: dict, status: Optional[dict] = None, state: Optional[dict] = None) -> dict:
    status = status or {}
    state = state or read_json(cfg['state_file']) or {}
    chrome_ok = bool(status.get('chrome_running')) if 'chrome_running' in status else chrome_running(cfg['remote_debugging_port'])
    last_success = bool(state.get('success')) if isinstance(state, dict) else False
    token_config_ok = not _token_looks_like_url(cfg.get('connection_token', '')) and bool((cfg.get('connection_token') or '').strip())
    python_bin = str(Path(__file__).resolve().parent.parent / '.venv' / 'bin' / 'python')
    runtime_python = python_bin if Path(python_bin).exists() else os.environ.get('PYTHON', '') or 'python3'
    checks = {
        'chrome_cdp': {'ok': chrome_ok, 'message': 'Chrome CDP 可连接' if chrome_ok else 'Chrome/CDP 不可连接'},
        'last_refresh': {'ok': last_success, 'message': '最近一次刷新成功' if last_success else '最近一次刷新失败或暂无记录'},
        'connection_token_config': {'ok': token_config_ok, 'message': 'Connection Token 看起来有效' if token_config_ok else 'Connection Token 为空或像是 URL，配置可疑'},
        'chrome_binary': {'ok': bool(which(cfg.get('chrome_binary', ''))), 'message': f"Chrome binary: {cfg.get('chrome_binary', '')}"},
        'runtime_python': {'ok': True, 'message': runtime_python},
    }
    problems = [v['message'] for v in checks.values() if not v['ok']]
    return {
        'ok': all(v['ok'] for v in checks.values()),
        'checks': checks,
        'problems': problems,
        'debug_port': cfg['remote_debugging_port'],
        'chrome_version': chrome_version(cfg['remote_debugging_port']),
        'last_state': state,
    }


def build_chrome_env(cfg: dict):
    env = os.environ.copy()
    env['DISPLAY'] = cfg['display']
    env.setdefault('XDG_RUNTIME_DIR', cfg.get('runtime_dir', '/var/lib/flow2api-host-agent/runtime'))
    env.setdefault('HOME', cfg.get('home_dir', '/var/lib/flow2api-host-agent'))
    return env


def build_chrome_cmd(cfg: dict):
    return [
        cfg['chrome_binary'],
        f"--remote-debugging-port={cfg['remote_debugging_port']}",
        f"--user-data-dir={cfg['chrome_profile_dir']}",
        '--no-first-run',
        '--no-default-browser-check',
        '--password-store=basic',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--disable-software-rasterizer',
        '--disable-session-crashed-bubble',
        '--mute-audio',
        cfg['start_url'],
    ]


def start_chrome(cfg: dict):
    Path(cfg['chrome_profile_dir']).mkdir(parents=True, exist_ok=True)
    runtime_dir = Path(cfg.get('runtime_dir', '/var/lib/flow2api-host-agent/runtime'))
    runtime_dir.mkdir(parents=True, exist_ok=True)
    ensure_parent(cfg['log_file'])
    log = open(cfg['log_file'], 'a', encoding='utf-8')
    env = build_chrome_env(cfg)
    cmd = build_chrome_cmd(cfg)
    proc = subprocess.Popen(cmd, stdout=log, stderr=log, env=env)
    return proc.pid


def _normalize_url(url: str) -> str:
    return (url or '').rstrip('/')


def _classify_prewarm_url(url: Optional[str]) -> dict:
    u = (url or '').lower()
    abnormal_markers = [
        'signin',
        'error=callback',
        '/api/auth/',
        'accounts.google.com',
    ]
    is_abnormal = any(m in u for m in abnormal_markers)
    return {
        'url': url,
        'is_abnormal': is_abnormal,
        'reason': 'auth_redirect_or_error_page' if is_abnormal else 'ok',
    }


def _load_last_good(cfg: dict) -> dict:
    p = Path(cfg.get('last_good_file', '/var/lib/flow2api-host-agent/last_good.json'))
    try:
        if p.exists():
            return json.loads(p.read_text('utf-8'))
    except Exception:
        pass
    return {}


def _save_last_good(cfg: dict, data: dict):
    p = Path(cfg.get('last_good_file', '/var/lib/flow2api-host-agent/last_good.json'))
    try:
        ensure_parent(str(p))
        p.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    except Exception:
        pass


def _should_allow_aggressive(cfg: dict) -> bool:
    """Rate-limit aggressive navigation to avoid bumping the login session."""
    min_min = int(cfg.get('min_aggressive_interval_minutes', 240) or 240)
    now = int(time.time())
    lg = _load_last_good(cfg)
    last_ts = int(lg.get('last_aggressive_ts') or 0)
    return (now - last_ts) >= max(0, min_min) * 60


def _mark_aggressive_used(cfg: dict):
    lg = _load_last_good(cfg)
    lg['last_aggressive_ts'] = int(time.time())
    _save_last_good(cfg, lg)


def _choose_best_st_cookie(cookies: list) -> Optional[str]:
    """Pick the most likely 'current' session token cookie.

    Prefer:
    - domain that contains 'labs.google' or 'google'
    - latest expires
    - longest value (heuristic)
    """
    candidates = [c for c in (cookies or []) if c.get('name') == '__Secure-next-auth.session-token' and c.get('value')]
    if not candidates:
        return None

    def score(c):
        domain = (c.get('domain') or '').lstrip('.').lower()
        exp = c.get('expires')
        try:
            exp = float(exp) if exp is not None else -1
        except Exception:
            exp = -1
        vlen = len(c.get('value') or '')
        domain_bonus = 0
        if 'labs.google' in domain:
            domain_bonus = 3
        elif 'google' in domain:
            domain_bonus = 2
        elif domain:
            domain_bonus = 1
        # higher is better
        return (domain_bonus, exp, vlen)

    best = max(candidates, key=score)
    return best.get('value')


def _collect_cookies_and_st(browser):
    cookies = []
    for ctx in browser.contexts:
        try:
            cookies.extend(ctx.cookies())
        except Exception:
            pass

    st = _choose_best_st_cookie(cookies)
    return cookies, st


def _find_candidate_page(browser, start_url: str):
    start_url_n = _normalize_url(start_url)
    start_host = urlparse(start_url).hostname or 'labs.google'

    for ctx in browser.contexts:
        try:
            for page in ctx.pages:
                try:
                    page_url = page.url or ''
                    if _normalize_url(page_url).startswith(start_url_n):
                        return page, 'exact'
                    host = urlparse(page_url).hostname or ''
                    if host.endswith(start_host) or host.endswith('google.com'):
                        return page, 'related'
                except Exception:
                    pass
        except Exception:
            pass
    return None, 'none'


def _soft_prewarm(browser, cfg: dict):
    """Non-intrusive prewarm: do not force navigation unless necessary."""
    start_url = cfg.get('start_url', 'https://labs.google/fx/vi/tools/flow')
    settle_ms = int(cfg.get('prewarm_settle_ms', 5000))
    page, mode = _find_candidate_page(browser, start_url)

    if page is not None:
        try:
            page.wait_for_load_state('domcontentloaded', timeout=5000)
        except Exception:
            pass
        time.sleep(max(0, settle_ms) / 1000.0)
        page_url = getattr(page, 'url', None)
    else:
        page_url = None

    return {
        'strategy': 'soft',
        'mode': mode,
        'page_url': page_url,
        'page_state': _classify_prewarm_url(page_url),
        'settle_ms': settle_ms,
        'context_count': len(browser.contexts),
        'page_count': sum(len(ctx.pages) for ctx in browser.contexts),
    }


def _aggressive_prewarm(browser, cfg: dict):
    """Open a temporary Flow page like the extension, then close it after cookies settle."""
    start_url = cfg.get('start_url', 'https://labs.google/fx/vi/tools/flow')
    settle_ms = int(cfg.get('prewarm_settle_ms', 5000))
    nav_timeout_ms = int(cfg.get('prewarm_nav_timeout_ms', 45000))
    contexts = list(browser.contexts)
    if not contexts:
        raise RuntimeError('No browser contexts available for prewarm')

    temp_page = contexts[0].new_page()
    page_url = None
    mode = 'temp_page+goto'
    try:
        temp_page.goto(start_url, wait_until='load', timeout=nav_timeout_ms)
        try:
            temp_page.wait_for_load_state('networkidle', timeout=min(nav_timeout_ms, 15000))
        except Exception:
            pass
        time.sleep(max(0, settle_ms) / 1000.0)
        page_url = getattr(temp_page, 'url', None)
    finally:
        try:
            temp_page.close()
        except Exception:
            pass

    return {
        'strategy': 'aggressive',
        'mode': mode,
        'page_url': page_url,
        'page_state': _classify_prewarm_url(page_url),
        'settle_ms': settle_ms,
        'nav_timeout_ms': nav_timeout_ms,
        'context_count': len(browser.contexts),
        'page_count': sum(len(ctx.pages) for ctx in browser.contexts),
    }


def _run_aggressive_recovery(browser, cfg: dict, reason: str, force: bool = False):
    aggressive_info = _aggressive_prewarm(browser, cfg)
    _mark_aggressive_used(cfg)
    cookies, st = _collect_cookies_and_st(browser)
    aggressive_info['fallback_from'] = reason
    if force:
        aggressive_info['forced'] = True
    return cookies, st, aggressive_info


def _refresh_st_via_temp_page(cfg: dict):
    endpoint = f"http://127.0.0.1:{cfg['remote_debugging_port']}"
    with sync_playwright() as p:
        browser = p.chromium.connect_over_cdp(endpoint)
        prewarm_info = _aggressive_prewarm(browser, cfg)
        cookies, st = _collect_cookies_and_st(browser)
        browser.close()
        return st, cookies, prewarm_info


def attach_and_get_st(cfg: dict):
    endpoint = f"http://127.0.0.1:{cfg['remote_debugging_port']}"
    force_aggressive = bool(cfg.get('force_aggressive_prewarm'))
    with sync_playwright() as p:
        browser = p.chromium.connect_over_cdp(endpoint)
        soft_info = _soft_prewarm(browser, cfg)
        cookies, st = _collect_cookies_and_st(browser)
        prewarm_info = soft_info
        soft_page_state = (soft_info or {}).get('page_state') or {}

        # If force_aggressive_prewarm is enabled, always try a navigation/reload to refresh cookies.
        if force_aggressive:
            cookies, st, prewarm_info = _run_aggressive_recovery(browser, cfg, reason='soft', force=True)

        # If soft prewarm already sees an abnormal auth page, try one controlled recovery pass before giving up.
        elif soft_page_state.get('is_abnormal'):
            cookies, st, prewarm_info = _run_aggressive_recovery(browser, cfg, reason='soft_abnormal')
            prewarm_info['recovery_reason'] = soft_page_state.get('reason') or 'abnormal_page'

        # Default behavior: only aggressive when no session token present, and rate-limited.
        elif (not st) and _should_allow_aggressive(cfg):
            cookies, st, prewarm_info = _run_aggressive_recovery(browser, cfg, reason='soft')
        browser.close()
        return st, cookies, prewarm_info


def update_flow2api(cfg: dict, session_token: str):
    r = requests.post(
        cfg['flow2api_url'].rstrip('/') + '/api/plugin/update-token',
        headers={
            'Authorization': f"Bearer {cfg['connection_token']}",
            'Content-Type': 'application/json',
        },
        json={'session_token': session_token},
        timeout=60,
    )
    return r.status_code, r.text


def _mask_token(token: Optional[str], prefix: int = 8, suffix: int = 6):
    if not token:
        return None
    if len(token) <= prefix + suffix + 3:
        return token[:prefix] + '...'
    return f"{token[:prefix]}...{token[-suffix:]}"


def _token_fingerprint(token: Optional[str]):
    if not token:
        return None
    return hashlib.sha256(token.encode('utf-8')).hexdigest()[:16]


def _parse_update_body(body: str):
    try:
        return json.loads(body)
    except Exception:
        return None


def _flow2api_host(url: str) -> Optional[str]:
    try:
        return (urlparse(url).hostname or '').strip().lower() or None
    except Exception:
        return None


def _candidate_db_paths(cfg: dict):
    candidates = []
    explicit = cfg.get('flow2api_db_path')
    if explicit:
        candidates.append(explicit)
    candidates.extend(['/opt/apps/flow2api/data/flow.db', '/app/data/flow.db'])
    seen = set()
    out = []
    for p in candidates:
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _parse_at_expires(value):
    if not value:
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    if not isinstance(value, str):
        return None

    text = value.strip()
    if not text:
        return None
    if text.endswith('Z'):
        text = text[:-1] + '+00:00'
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _is_at_still_valid(value, skew_seconds: int = 60):
    dt = _parse_at_expires(value)
    if dt is None:
        return None
    return dt.timestamp() > (time.time() + max(0, skew_seconds))


def _verify_token_written_locally(cfg: dict, email: Optional[str], expected_st: Optional[str]):
    if not expected_st:
        return {'available': False, 'verified': False, 'reason': 'missing_email_or_expected_token'}

    last_error = None
    for db_path in _candidate_db_paths(cfg):
        p = Path(db_path)
        if not p.exists():
            last_error = f'db_not_found:{db_path}'
            continue
        try:
            con = sqlite3.connect(str(p))
            cur = con.cursor()
            lookup_reason = 'email'
            row = None
            if email:
                row = cur.execute(
                    'SELECT id, email, st, at_expires, is_active, current_project_id, current_project_name FROM tokens WHERE email = ? ORDER BY id DESC LIMIT 1',
                    (email,),
                ).fetchone()
            if not row:
                lookup_reason = 'st'
                row = cur.execute(
                    'SELECT id, email, st, at_expires, is_active, current_project_id, current_project_name FROM tokens WHERE st = ? ORDER BY id DESC LIMIT 1',
                    (expected_st,),
                ).fetchone()
            con.close()
            if not row:
                return {
                    'available': True,
                    'verified': False,
                    'db_path': db_path,
                    'reason': 'email_or_st_not_found' if email else 'st_not_found',
                    'email': email,
                    'lookup': lookup_reason,
                }
            token_id, row_email, stored_st, at_expires, is_active, current_project_id, current_project_name = row
            stored_fp = _token_fingerprint(stored_st)
            expected_fp = _token_fingerprint(expected_st)
            matched = stored_st == expected_st
            at_valid = _is_at_still_valid(at_expires)
            return {
                'available': True,
                'verified': matched,
                'db_path': db_path,
                'token_id': token_id,
                'email': row_email,
                'is_active': bool(is_active),
                'at_expires': at_expires,
                'at_valid': at_valid,
                'current_project_id': current_project_id,
                'current_project_name': current_project_name,
                'expected_st_fingerprint': expected_fp,
                'stored_st_fingerprint': stored_fp,
                'stored_st_masked': _mask_token(stored_st),
                'lookup': lookup_reason,
                'reason': 'matched' if matched else 'st_mismatch',
            }
        except Exception as e:
            last_error = repr(e)
            continue

    return {'available': False, 'verified': False, 'reason': last_error or 'verification_unavailable'}


def _run_once_inner(cfg: dict):
    started = time.time()
    st, cookies, prewarm_info = attach_and_get_st(cfg)
    result = {
        'time': int(started),
        'cookie_count': len(cookies),
        'has_session_token': bool(st),
        'remote_debugging_port': cfg['remote_debugging_port'],
        'flow2api_url': cfg.get('flow2api_url'),
        'flow2api_host': _flow2api_host(cfg.get('flow2api_url', '')),
        'prewarm': prewarm_info,
    }

    page_state = (prewarm_info or {}).get('page_state') or {}
    strategy = (prewarm_info or {}).get('strategy')
    if page_state.get('is_abnormal') and strategy == 'aggressive':
        result['prewarm_warning'] = f"Aggressive prewarm landed on abnormal page: {page_state.get('url')}"
    elif page_state.get('is_abnormal') and strategy == 'soft':
        result['prewarm_warning'] = f"Observed abnormal page in browser, but soft mode did not force navigation: {page_state.get('url')}"

    if st:
        result['session_token_masked'] = _mask_token(st)
        result['session_token_fingerprint'] = _token_fingerprint(st)

        # Guardrail: soft abnormal pages are still too risky to trust.
        # But when plugin-style temp-page recovery already extracted a fresh ST,
        # continue and rely on downstream write verification instead of failing early.
        if page_state.get('is_abnormal') and strategy != 'aggressive':
            result['success'] = False
            result['error'] = 'Abnormal page state; refusing to update token to avoid overwriting a good session'
            result['skipped_update'] = True
            lg = _load_last_good(cfg)
            result['last_good_st_fingerprint'] = lg.get('last_good_st_fingerprint')
            result['last_good_time'] = lg.get('last_good_time')
            return result
        if page_state.get('is_abnormal') and strategy == 'aggressive':
            result['abnormal_page_policy'] = 'allow_aggressive_sync'

        # Dedup: if ST fingerprint is unchanged since last known-good, skip updating.
        lg = _load_last_good(cfg)
        last_fp = lg.get('last_good_st_fingerprint')
        if last_fp and last_fp == result['session_token_fingerprint']:
            verify = _verify_token_written_locally(cfg, lg.get('last_good_email'), st)
            result['write_verification'] = verify
            if verify.get('email'):
                result['token_email'] = verify.get('email')

            # Only skip the push when Flow2API still has the same ST and the access token
            # is not known to be expired. Otherwise we fall through and repair the downstream state.
            if verify.get('available') and verify.get('verified') and verify.get('at_valid') is not False:
                lg['last_good_time'] = int(time.time())
                if verify.get('email'):
                    lg['last_good_email'] = verify.get('email')
                _save_last_good(cfg, lg)
                result['success'] = True
                result['skipped_update'] = True
                result['skip_reason'] = 'st_unchanged_verified'
                return result

            result['dedup_repair_required'] = True
            result['dedup_reason'] = verify.get('reason')
            result['dedup_at_valid'] = verify.get('at_valid')

            try:
                repaired_st, repaired_cookies, repaired_prewarm = _refresh_st_via_temp_page(cfg)
                repaired_fp = _token_fingerprint(repaired_st)
                result['repair_attempt'] = {
                    'strategy': (repaired_prewarm or {}).get('strategy'),
                    'mode': (repaired_prewarm or {}).get('mode'),
                    'page_url': (repaired_prewarm or {}).get('page_url'),
                    'page_state': (repaired_prewarm or {}).get('page_state'),
                    'before_fingerprint': last_fp,
                    'after_fingerprint': repaired_fp,
                }
                if repaired_st and repaired_fp and repaired_fp != result['session_token_fingerprint']:
                    st = repaired_st
                    cookies = repaired_cookies
                    prewarm_info = repaired_prewarm
                    page_state = (prewarm_info or {}).get('page_state') or {}
                    strategy = (prewarm_info or {}).get('strategy')
                    result['cookie_count'] = len(cookies)
                    result['session_token_masked'] = _mask_token(st)
                    result['session_token_fingerprint'] = repaired_fp
                    result['prewarm'] = prewarm_info
                    result['repair_attempt']['st_changed'] = True
                else:
                    result['repair_attempt']['st_changed'] = False
            except Exception as e:
                result['repair_attempt_error'] = repr(e)

        status, body = update_flow2api(cfg, st)
        result['update_status'] = status
        result['update_body'] = body[:2000]

        parsed_body = _parse_update_body(body)
        if parsed_body is not None:
            result['update_json'] = parsed_body
            result['update_api_success'] = bool(parsed_body.get('success'))
            result['update_action'] = parsed_body.get('action')
            result['token_email'] = parsed_body.get('email') or parsed_body.get('token_email')
            msg = parsed_body.get('message')
            if isinstance(msg, str) and not result.get('token_email'):
                marker = ' for '
                if marker in msg:
                    maybe_email = msg.split(marker, 1)[1].strip()
                    if '@' in maybe_email:
                        result['token_email'] = maybe_email
        else:
            result['update_api_success'] = False
            result['update_parse_error'] = 'response_not_json'

        verify = _verify_token_written_locally(cfg, result.get('token_email'), st)
        result['write_verification'] = verify

        api_ok = status == 200 and bool(result.get('update_api_success')) and result.get('update_action') in {'updated', 'added'}
        if verify.get('available'):
            result['success'] = bool(api_ok and verify.get('verified'))
            if not result['success'] and api_ok and not verify.get('verified'):
                result['error'] = f"Write verification failed: {verify.get('reason')}"
            elif result['success'] and verify.get('at_valid') is False:
                result['warning'] = (
                    'Session Token 已同步到 Flow2API，但当前 AT 仍然处于过期状态。'
                    '这通常说明 /api/plugin/update-token 只完成了 ST 同步，没有顺手刷新 AT。'
                )
        else:
            result['success'] = bool(api_ok)
            result['warning'] = f"API update succeeded but local verification unavailable: {verify.get('reason')}"

        # Record last-known-good only after we have a successful update.
        if result.get('success'):
            lg = _load_last_good(cfg)
            lg['last_good_st_fingerprint'] = result.get('session_token_fingerprint')
            lg['last_good_time'] = int(time.time())
            if result.get('token_email'):
                lg['last_good_email'] = result.get('token_email')
            _save_last_good(cfg, lg)
    else:
        result['success'] = False
        result['error'] = 'No session token found'

    return result


def run_once(cfg: dict):
    retry_count = int(cfg.get('retry_count', 1))
    retry_delay_ms = int(cfg.get('retry_delay_ms', 3000))

    attempts = []
    final = None
    for i in range(retry_count + 1):
        result = _run_once_inner(cfg)
        result['attempt'] = i + 1
        attempts.append(dict(result))
        final = dict(result)
        if result.get('success'):
            break
        if i < retry_count:
            time.sleep(max(0, retry_delay_ms) / 1000.0)

    if final is None:
        final = {'time': int(time.time()), 'success': False, 'error': 'No attempts executed'}

    final['attempts'] = attempts
    final['attempt_count'] = len(attempts)
    if len(attempts) > 1:
        final['retried'] = True

    recovery_attempt = next(
        (
            attempt for attempt in attempts
            if ((attempt.get('prewarm') or {}).get('fallback_from') == 'soft_abnormal')
        ),
        None,
    )
    if recovery_attempt:
        recovery_prewarm = recovery_attempt.get('prewarm') or {}
        recovery_page = recovery_prewarm.get('page_state') or {}
        final['recovery_attempted'] = True
        final['recovery_attempt'] = {
            'attempt': recovery_attempt.get('attempt'),
            'strategy': recovery_prewarm.get('strategy'),
            'mode': recovery_prewarm.get('mode'),
            'page_url': recovery_prewarm.get('page_url'),
            'page_state': recovery_page,
        }
        if not final.get('success') and recovery_page.get('is_abnormal'):
            final['prewarm_warning'] = (
                'Tried aggressive recovery once, but browser still landed on an abnormal auth page: '
                f"{recovery_page.get('url')}"
            )

    save_json(cfg['state_file'], final)
    return final
