const form = document.querySelector('#shorten-form');
const button = form.querySelector('button');
const error = document.querySelector('#error');
const result = document.querySelector('#result');

form.addEventListener('submit', async (event) => {
  event.preventDefault(); error.classList.add('hidden'); result.classList.add('hidden');
  button.disabled = true; button.textContent = 'Creating…';
  try {
    const response = await fetch('/api/v1/shorten', {
      method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': form.elements.apiKey.value },
      body: JSON.stringify({ url: form.elements.url.value }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Could not shorten this URL.');
    const link = document.querySelector('#short-url'); link.href = data.shortUrl; link.textContent = data.shortUrl;
    result.classList.remove('hidden');
  } catch (problem) {
    error.textContent = problem.message || 'Could not connect to the server.'; error.classList.remove('hidden');
  } finally { button.disabled = false; button.textContent = 'Shorten URL'; }
});
