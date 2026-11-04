document.querySelectorAll('[data-subscribe]').forEach((section) => {
  const form = section.querySelector('[data-subscribe-form]');
  const button = form.querySelector('button[type="submit"]');
  const hint = section.querySelector('.blog-subscribe__hint');
  const update = () => {
    const choice = form.querySelector('[name="subscription-scope"]:checked');
    const action = choice.dataset.action;
    if (action) form.setAttribute('action', action);
    else form.removeAttribute('action');
    button.disabled = !action;
    hint.textContent = action ? 'Unsubscribe anytime.' : 'Email subscriptions are coming soon.';
  };
  form.querySelectorAll('[name="subscription-scope"]').forEach((choice) => {
    choice.addEventListener('change', update);
  });
  form.addEventListener('submit', (event) => {
    // Never submit an email to the blog when a feed has not been connected.
    if (!form.getAttribute('action')) event.preventDefault();
  });
  update();
});
