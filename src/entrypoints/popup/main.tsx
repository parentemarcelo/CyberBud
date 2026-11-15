import { render } from 'preact';
import { App } from '../../ui/App';
import '../../assets/base.css';

render(<App mode="popup" />, document.getElementById('app')!);
