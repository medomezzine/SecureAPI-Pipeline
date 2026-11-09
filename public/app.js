document.querySelector('#load').addEventListener('click', async () => {
  const response = await fetch('/notes', { headers: { Authorization: `Bearer ${document.querySelector('#token').value}` } });
  const notes = await response.json();
  const list = document.querySelector('#notes');
  list.replaceChildren();
  for (const note of notes) {
    const item = document.createElement('li');
    item.textContent = `${note.title}: ${note.content}`; // textContent displays notes as text, not HTML.
    list.append(item);
  }
});
