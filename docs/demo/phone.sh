#!/usr/bin/env bash
# ---
# relationships:
#   verifies: web-interface
# ---
#
# Tests the web interface at phone width with agent-browser, against the site
# that docs/demo/web.sh has walked through: the teal policy, its binding of
# teal-api, and a pending operator key. web.sh runs it last; it also runs alone
# against a site in that state. It checks that the page heading, the primary
# action, and the tab list of the policy editor and the binding editor start in
# the first screen, that each editor's tabs keep one row with a faded edge
# where tabs are out of sight, that the arrow keys move visible focus through
# each tab inside the row, and that the navigation menu works with pointer and
# keyboard. It prints each measurement and exits 1 after the last check when
# any check failed. It also captures docs/user/assets/web-phone-menu.png.
set -euo pipefail

repository=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
site=${WYRWOOD_DEMO_SITE:-http://localhost:18088}
assets=$repository/docs/user/assets
export AGENT_BROWSER_SESSION=${AGENT_BROWSER_SESSION:-wyrwood-demo-web}
width=390
height=844
failed=0
toggle='document.querySelector("nav[aria-label=Primary] button[aria-controls]")'
destinations='["Agents", "Bindings", "Policies", "OpenBao keys", "Operator keys", "Events", "Settings"]'

browse() {
	agent-browser "$@" >/dev/null
}

# Runs a script in the page that returns "ok" or the reason it failed. A check
# that cannot run in the page fails too. focused() names the focused element
# without its content, so that no page value reaches the log.
check() {
	local got
	got=$(agent-browser eval "(() => {
		const focused = () => document.activeElement.tagName + ' ' + (document.activeElement.getAttribute('href') || document.activeElement.className || '');
		return $2;
	})()" 2>&1) || true
	if [ "$got" = '"ok"' ]; then
		echo "phone.sh: ok   $1"
	else
		echo "phone.sh: FAIL $1: $got" >&2
		failed=1
	fi
}

# Prints the document top of each named control after the page scrolled to the
# top. A control that is absent prints "absent".
measure() {
	agent-browser eval "(() => {
		window.scrollTo(0, 0);
		const top = (el) => el ? Math.round(el.getBoundingClientRect().top + window.scrollY) : 'absent';
		const button = (name) => [...document.querySelectorAll('main button')].find((b) => b.textContent.trim() === name);
		return '$1 at ' + window.innerWidth + 'x' + window.innerHeight
			+ ': heading ' + top(document.querySelector('.topbar h1'))
			+ ', $2 ' + top(button('$2'))
			+ ', tab list ' + top(document.querySelector('main [role=tablist]'));
	})()"
}

# Fails a check unless each named control starts above the first screen's end.
first_screen() {
	check "$1: heading, $2 and tab list start above y $height" "(() => {
		window.scrollTo(0, 0);
		if (window.scrollY !== 0) return 'page did not scroll to the top';
		if (window.innerHeight !== $height) return 'viewport height ' + window.innerHeight;
		const button = [...document.querySelectorAll('main button')].find((b) => b.textContent.trim() === '$2');
		const controls = { heading: document.querySelector('.topbar h1'), '$2': button, 'tab list': document.querySelector('main [role=tablist]') };
		const late = Object.entries(controls).filter(([, el]) => !el || el.getBoundingClientRect().top >= $height);
		return late.length ? 'below the first screen or absent: ' + late.map(([name]) => name).join(', ') : 'ok';
	})()"
}

# Fails a check unless the tabs share one row and the tab list ends in the
# first screen.
one_row() {
	check "$1: tabs in one row that ends above y $height" "(() => {
		window.scrollTo(0, 0);
		const list = document.querySelector('main [role=tablist]');
		const tabs = list ? [...list.querySelectorAll('[role=tab]')] : [];
		if (tabs.length < 2) return 'tab list has ' + tabs.length + ' tabs';
		const tops = [...new Set(tabs.map((t) => Math.round(t.getBoundingClientRect().top + window.scrollY)))];
		if (tops.length !== 1) return 'tabs start at y ' + tops.join(', ');
		const bottom = Math.round(list.getBoundingClientRect().bottom);
		return bottom <= $height ? 'ok' : 'tab list ends at y ' + bottom;
	})()"
}

# Grades the tab list's sign that tabs are out of sight: each side is marked
# exactly when the list scrolls further that way, and a marked list is faded.
more_sign() {
	check "$1: the tab list marks the sides with tabs out of sight" "(() => {
		const list = document.querySelector('main [role=tablist]');
		const before = list.scrollLeft > 1;
		const after = list.scrollLeft + list.clientWidth < list.scrollWidth - 1;
		if (list.hasAttribute('data-more-start') !== before) return 'data-more-start is ' + list.hasAttribute('data-more-start') + ' at scrollLeft ' + list.scrollLeft;
		if (list.hasAttribute('data-more-end') !== after) return 'data-more-end is ' + list.hasAttribute('data-more-end') + ' with ' + (list.scrollWidth - list.clientWidth - list.scrollLeft) + ' px to the end';
		const mask = getComputedStyle(list).maskImage || getComputedStyle(list).webkitMaskImage;
		return (before || after) === (mask !== 'none') ? 'ok' : 'mask ' + mask;
	})()"
}

# Tab moves focus to the selected tab, and the arrow keys move it through
# each tab. Each focused tab and its focus outline must be inside the tab
# list's visible box. The tabs move focus from a timer after an arrow key, so
# each check first lets the page's pending timers run.
tabs_by_keyboard() {
	browse eval "window.scrollTo(0, 0); document.activeElement.blur(); true"
	for _ in $(seq 40); do
		browse press Tab
		if [ "$(agent-browser eval 'document.activeElement.getAttribute("role")')" = '"tab"' ]; then
			break
		fi
	done
	local count
	count=$(agent-browser eval "document.querySelectorAll('main [role=tablist] [role=tab]').length")
	for index in $(seq "$count"); do
		check "$1: tab $index has visible focus inside the tab list" "new Promise((settle) => setTimeout(settle)).then(() => {
			const tab = document.activeElement;
			const list = tab.closest('main [role=tablist]');
			if (!list || tab.getAttribute('role') !== 'tab') return 'focus on ' + focused();
			if (tab !== list.querySelectorAll('[role=tab]')[$index - 1]) return 'focus on tab ' + ([...list.querySelectorAll('[role=tab]')].indexOf(tab) + 1);
			const style = getComputedStyle(tab);
			if (!tab.matches(':focus-visible') || style.outlineStyle === 'none') return 'no visible focus';
			// A list that clips its content must hold the whole focus outline.
			const ring = getComputedStyle(list).overflowX === 'visible' ? 0 : parseFloat(style.outlineWidth) + parseFloat(style.outlineOffset);
			const box = list.getBoundingClientRect();
			const r = tab.getBoundingClientRect();
			const inside = r.left - ring >= box.left - 0.5 && r.right + ring <= box.right + 0.5 && r.top - ring >= box.top - 0.5 && r.bottom + ring <= box.bottom + 0.5;
			return inside ? 'ok' : 'tab or outline outside the list: tab ' + Math.round(r.left) + '..' + Math.round(r.right) + ', list ' + Math.round(box.left) + '..' + Math.round(box.right);
		})"
		more_sign "$1 with tab $index focused"
		browse press ArrowRight
	done
}

# The page must show its own heading before any position is graded.
on_page() {
	check "reached $1" "(() => {
		const heading = document.querySelector('.topbar h1');
		return location.pathname.startsWith('$2') && heading ? 'ok' : 'at ' + location.pathname + ', heading ' + (heading && heading.textContent);
	})()"
}


# The binding editor's tab list position at 1280 x 800 is the desktop evidence
# that the layout did not change there.
browse set viewport 1280 800
browse open "$site/bindings"
# Run alone, the browser has no session yet.
if [ "$(agent-browser eval 'Boolean(document.querySelector("nav[aria-label=Primary]"))')" != true ]; then
	browse find role button click --name "Continue with Example ID"
	browse wait --text "Approved agents"
	browse open "$site/bindings"
fi
browse find role link click --name "Edit binding for teal-api"
browse wait "main [role=tablist]"
on_page "binding editor at 1280 x 800" /bindings/
measure "binding editor" "Save binding"
check "binding editor at 1280 x 800: tabs in one row" "(() => {
	const tabs = [...document.querySelectorAll('main [role=tablist] [role=tab]')];
	const tops = new Set(tabs.map((t) => Math.round(t.getBoundingClientRect().top)));
	const list = document.querySelector('main [role=tablist]');
	if (tabs.length < 2 || tops.size !== 1) return tabs.length + ' tabs at ' + tops.size + ' tops';
	return list.scrollWidth === list.clientWidth ? 'ok' : 'tab list scrolls at 1280 x 800';
})()"
check "navigation beside the page shows each destination and no menu control" "(() => {
	const control = $toggle;
	if (control && control.checkVisibility()) return 'menu control is displayed';
	const nav = document.querySelector('nav[aria-label=Primary]').getBoundingClientRect();
	if (nav.right > document.querySelector('.page').getBoundingClientRect().left) return 'navigation is not beside the page';
	const links = [...document.querySelectorAll('nav .nav-links a')];
	const missing = $destinations.filter((name) => !links.some((a) => a.firstChild && a.firstChild.textContent === name && a.checkVisibility()));
	if (missing.length) return 'not shown: ' + missing.join(', ');
	const account = [...document.querySelectorAll('nav button')].find((b) => b.textContent.startsWith('Account'));
	const gap = nav.bottom - account.getBoundingClientRect().bottom;
	return nav.height === window.innerHeight && Math.round(gap) <= 24 ? 'ok' : 'account is ' + gap + ' px above the foot of a ' + nav.height + ' px sidebar';
})()"

browse set viewport "$width" "$height"
browse open "$site/policies/edit?name=teal"
browse wait --text "1 binding on 1 agent"
on_page "policy editor" /policies/edit
measure "policy editor" "Save and validate"
first_screen "policy editor" "Save and validate"
one_row "policy editor"
more_sign "policy editor"
tabs_by_keyboard "policy editor"

browse open "$site/bindings"
browse find role link click --name "Edit binding for teal-api"
browse wait "main [role=tablist]"
on_page "binding editor" /bindings/
measure "binding editor" "Save binding"
first_screen "binding editor" "Save binding"
one_row "binding editor"
more_sign "binding editor"
tabs_by_keyboard "binding editor"

if [ "$(agent-browser eval "Boolean($toggle)")" != true ]; then
	echo "phone.sh: FAIL no menu control in the primary navigation" >&2
	exit 1
fi

# Closed on load: one control, and no destination shown.
browse open "$site/agents"
browse wait --text "Approved agents"
check "menu control is a named, closed button" "(() => {
	const control = $toggle;
	const panel = document.getElementById(control.getAttribute('aria-controls'));
	if (control.tagName !== 'BUTTON' || control.textContent.trim() !== 'Menu') return 'control is ' + control.outerHTML;
	if (control.getAttribute('aria-expanded') !== 'false') return 'aria-expanded ' + control.getAttribute('aria-expanded');
	if (!panel || !control.closest('nav').contains(panel)) return 'aria-controls names no panel in the navigation';
	if (control.getBoundingClientRect().height < 44) return 'control is ' + control.getBoundingClientRect().height + ' px high';
	const shown = [...document.querySelectorAll('nav a, nav button')].filter((el) => el !== control && el.checkVisibility());
	return shown.every((el) => el.classList.contains('brand')) ? 'ok' : 'shown while closed: ' + shown.map((el) => el.textContent.trim()).join(', ');
})()"

# Pointer: the control opens and closes the panel.
browse click "nav[aria-label=Primary] button[aria-controls]"
check "pointer opens the menu" "$toggle.getAttribute('aria-expanded') === 'true' ? 'ok' : 'still closed'"
check "open menu shows each destination, its pending count, the OpenBao status, Report an issue and Account" "(() => {
	const links = [...document.querySelectorAll('nav .nav-links a')];
	const missing = $destinations.filter((name) => {
		const link = links.find((a) => a.firstChild && a.firstChild.textContent === name);
		return !link || !link.checkVisibility() || link.getBoundingClientRect().height < 44;
	});
	if (missing.length) return 'not shown at 44 px: ' + missing.join(', ');
	const count = links.find((a) => a.firstChild.textContent === 'Operator keys').querySelector('.count');
	if (!count || !count.checkVisibility() || count.getAttribute('aria-label') !== count.textContent + ' pending') return 'operator key pending count not shown';
	const foot = document.querySelector('nav .nav-foot');
	if (!foot || !foot.checkVisibility() || !/OpenBao (reachable|unreachable)/.test(foot.textContent)) return 'OpenBao status not shown';
	const report = [...foot.querySelectorAll('a')].find((a) => a.textContent.startsWith('Report an issue'));
	if (!report || !report.checkVisibility()) return 'Report an issue not shown';
	const account = [...document.querySelectorAll('nav button')].find((b) => b.textContent.startsWith('Account'));
	return account && account.checkVisibility() ? 'ok' : 'Account not shown';
})()"
browse eval "window.scrollTo(0, 0)"
browse eval "document.fonts.ready.then(() => true)"
browse screenshot "$assets/web-phone-menu.png"
browse click "nav[aria-label=Primary] button[aria-controls]"
check "pointer closes the menu" "$toggle.getAttribute('aria-expanded') === 'false' && !document.querySelector('nav .nav-links').checkVisibility() ? 'ok' : 'still open'"

# Keyboard: Tab reaches the control after the brand link, Enter and Space open
# it, Tab reaches each destination with visible focus, and Escape closes it and
# returns focus to the control.
browse reload
browse wait --text "Approved agents"
browse press Tab
browse press Tab
check "Tab focuses the control with visible focus" "(() => {
	const control = $toggle;
	if (document.activeElement !== control) return 'focus on ' + focused();
	return control.matches(':focus-visible') && getComputedStyle(control).outlineStyle !== 'none' ? 'ok' : 'no visible focus';
})()"
browse press Enter
check "Enter opens the menu" "$toggle.getAttribute('aria-expanded') === 'true' ? 'ok' : 'still closed'"
for name in Agents Bindings Policies "OpenBao keys" "Operator keys" Events Settings; do
	for _ in 1 2; do
		browse press Tab
		if [ "$(agent-browser eval 'document.activeElement.firstChild && document.activeElement.firstChild.textContent')" = "\"$name\"" ]; then
			break
		fi
	done
	check "Tab reaches $name with visible focus" "(() => {
		const item = document.activeElement;
		if (!item.closest('nav .nav-links') || item.firstChild.textContent !== '$name') return 'focus on ' + focused();
		const style = getComputedStyle(item);
		return item.matches(':focus-visible') && style.outlineStyle !== 'none' && style.outlineColor === 'rgb(201, 212, 205)' ? 'ok' : 'focus outline ' + style.outlineStyle + ' ' + style.outlineColor;
	})()"
done
browse press Escape
check "Escape closes the menu and returns focus to the control" "(() => {
	const control = $toggle;
	if (control.getAttribute('aria-expanded') !== 'false') return 'still open';
	return document.activeElement === control ? 'ok' : 'focus on ' + focused();
})()"
browse press Space
check "Space opens the menu" "$toggle.getAttribute('aria-expanded') === 'true' ? 'ok' : 'still closed'"
browse press Escape
check "Escape on the control closes the menu" "$toggle.getAttribute('aria-expanded') === 'false' && document.activeElement === $toggle ? 'ok' : 'still open or focus moved'"
browse press Enter
for _ in 1 2 3 4 5 6 7; do
	browse press Tab
	if [ "$(agent-browser eval 'document.activeElement.firstChild && document.activeElement.firstChild.textContent')" = '"Events"' ]; then
		break
	fi
done
browse press Enter
browse wait --text "Controller events, newest first"
check "Enter on Events opens Events with the menu closed" "(() => {
	const control = $toggle;
	return location.pathname === '/events' && control.getAttribute('aria-expanded') === 'false' ? 'ok' : 'at ' + location.pathname + ', aria-expanded ' + control.getAttribute('aria-expanded');
})()"

exit "$failed"
