import { render } from 'preact';
import '../../assets/base.css';

function Options() {
  return (
    <main class="options">
      <h1>CyberBud Settings</h1>
      <p>API keys and preferences arrive in PLAN step 21.</p>
    </main>
  );
}

render(<Options />, document.getElementById('app')!);
