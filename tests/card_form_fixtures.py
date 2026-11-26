"""Synthetic card forms shared by the CDP and extension route tests. No real card data."""


# Modelled on a card form in the merchant's own main frame: plain inputs with no
# autocomplete hint, and expiry month and year as ARIA dropdown buttons whose
# listbox the page renders (into the body, a moment later) only while open.
HINTLESS = """<!doctype html><title>Synthetic hint-less card form</title>
<style>input,button{display:block;width:230px;height:25px;margin:5px}
[role=listbox]{position:absolute;left:300px;top:0;width:120px;background:#fff;border:1px solid #888}
[role=option]{height:18px}</style>
<form id=pay onsubmit="events.push('submit');return false">
<input id=pidlInput_accountToken type=text aria-label="Card number">
<input id=pidlInput_cvvToken type=text aria-label="CVV">
<input id=hint-on type=text autocomplete=on aria-label="Card number">
<input id=hint-off type=text autocomplete=off aria-label="Card number">
<input id=conflict type=text autocomplete=cc-csc aria-label="Card number">
<input id=sub-hint type=text autocomplete="shipping cc-number" aria-label="Card number">
<button type=button id=pidlInput_expiryMonth aria-haspopup=listbox aria-expanded=false aria-controls=month-list
  data-options="01 02 03 04 05 06 07 08 09 10 11 12"><span>Month</span><i>v</i></button>
<button type=button id=pidlInput_expiryYear aria-haspopup=listbox aria-expanded=false aria-controls=year-list
  data-options="2026 2027 2028 2029 2030 2031 2032 2033 2034 2035"><span>Year</span><i>v</i></button>
<button type=button id=short-year aria-haspopup=listbox aria-expanded=false aria-controls=short-list
  data-options="26 27 28 29 30 31 32 33 34 35"><span>YY</span></button>
<div id=combo-month role=combobox tabindex=0 aria-expanded=false aria-owns=combo-list
  data-options="1 2 3 4 5 6 7 8 9 10 11 12"><span>Month</span></div>
<button type=button id=ambiguous aria-haspopup=listbox aria-expanded=false aria-controls=ambiguous-list
  data-options="8 9 09 10"><span>Month</span></button>
<button type=button id=no-match aria-haspopup=listbox aria-expanded=false aria-controls=named-list
  data-options="January February March April May June July August September October November December"><span>Month</span></button>
<button type=button id=disabled-match aria-haspopup=listbox aria-expanded=false aria-controls=disabled-list
  data-options="08 09 10" data-disabled="09"><span>Month</span></button>
<button type=button id=never-opens aria-haspopup=listbox aria-expanded=false aria-controls=missing-list
  data-options="09" data-inert=1><span>Month</span></button>
<button type=button id=zero-based-names aria-haspopup=listbox aria-expanded=false aria-controls=zero-list
  data-options="January February March April May June July August September October November December"
  data-values="0 1 2 3 4 5 6 7 8 9 10 11"><span>Month</span></button>
<button type=button id=one-based-names aria-haspopup=listbox aria-expanded=false aria-controls=one-list
  data-options="January February March April May June July August September October November December"
  data-values="1 2 3 4 5 6 7 8 9 10 11 12"><span>Month</span></button>
<button type=button id=stale-label aria-haspopup=listbox aria-expanded=false aria-controls=stale-list
  data-options="1 2 3 4 5 6 7 8 9 10 11 12" data-values="0 1 2 3 4 5 6 7 8 9 10 11" data-dead=1><span>8</span></button>
<button type=button id=plain-button data-options="01 02 03 04 05 06 07 08 09 10 11 12"><span>Month</span></button>
<button id=submit-dropdown aria-haspopup=listbox aria-expanded=false aria-controls=submit-list
  data-options="01 02 03 04 05 06 07 08 09 10 11 12"><span>Month</span></button>
<button type=button id=menu-dropdown aria-haspopup=menu aria-expanded=false aria-controls=menu-list
  data-options="01 02 03 04 05 06 07 08 09 10 11 12"><span>Month</span></button>
<button type=button id=two-lists aria-haspopup=listbox aria-expanded=false aria-controls=list-a aria-owns=list-b
  data-options="01 02 03 04 05 06 07 08 09 10 11 12"><span>Month</span></button>
</form>
<script>
window.events = [];
document.addEventListener('input', e => events.push('input:' + e.target.id));
document.addEventListener('keydown', () => events.push('key'));
for (const button of document.querySelectorAll('[data-options]')) {
  const id = button.getAttribute('aria-controls') || button.getAttribute('aria-owns') || button.id + '-list';
  button.addEventListener('click', () => {
    const old = document.getElementById(id);
    if (button.getAttribute('aria-expanded') === 'true') {
      if (old) old.remove();
      button.setAttribute('aria-expanded', 'false'); events.push('close:' + button.id); return;
    }
    button.setAttribute('aria-expanded', 'true');
    events.push('open:' + button.id);
    // Like a framework render: the options appear after the click returns.
    setTimeout(() => {
      if (button.dataset.inert) return;
      const list = document.createElement('div');
      list.id = id; list.setAttribute('role', 'listbox');
      const values = (button.dataset.values || '').split(' ');
      for (const [index, label] of button.dataset.options.split(' ').entries()) {
        const option = document.createElement('div');
        if (button.dataset.values) option.dataset.value = values[index];
        option.setAttribute('role', 'option'); option.setAttribute('aria-selected', 'false');
        if (button.dataset.disabled === label) option.setAttribute('aria-disabled', 'true');
        option.textContent = label;
        // A widget that ignores the DOM click (it selects on another event).
        if (!button.dataset.dead) option.addEventListener('click', () => {
          button.firstElementChild.textContent = label;
          events.push('choose:' + button.id + '=' + label);
          list.remove(); button.setAttribute('aria-expanded', 'false');
        });
        list.append(option);
      }
      document.body.append(list);
    }, 40);
  });
}
</script>
"""
