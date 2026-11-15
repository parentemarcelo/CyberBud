import { setupBackground } from '../background/setup';

export default defineBackground({
  // Firefox MV3 runs the background as a non-persistent event page (SPEC §4).
  type: 'module',
  main() {
    setupBackground();
  },
});
