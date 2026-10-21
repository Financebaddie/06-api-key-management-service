const form = document.querySelector('#login-form');
const error = document.querySelector('#error');
form.addEventListener('submit', async (event) => {
  event.preventDefault(); error.classList.add('hidden');
  try {
    const response = await fetch('/api/admin/login', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify(Object.fromEntries(new FormData(form))),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Login failed.');
    window.location.assign('/admin');
  } catch (problem) { error.textContent = problem.message; error.classList.remove('hidden'); }
});
