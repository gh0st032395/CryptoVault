import { mount } from 'svelte';
import './app.css';
import App from './App.svelte';

const target = document.getElementById('app');
if (target === null) {
  throw new Error('the #app element is missing from index.html');
}

export default mount(App, { target });
