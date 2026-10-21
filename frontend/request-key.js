const form = document.querySelector('#request-form');
const error = document.querySelector('#error');
const button = form.querySelector('button');
form.elements.expiresAt.min = new Date().toISOString().slice(0, 10);

form.addEventListener('submit', async (event) => {
  event.preventDefault(); error.classList.add('hidden'); button.disabled = true;
  try {
    const response = await fetch('/api/key-requests', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify(Object.fromEntries(new FormData(form))),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Could not submit your request.');
    form.classList.add('hidden'); document.querySelector('#success').classList.remove('hidden');
  } catch (problem) {
    error.textContent = problem.message || 'Could not connect to the server.'; error.classList.remove('hidden');
  } finally { button.disabled = false; }
});
