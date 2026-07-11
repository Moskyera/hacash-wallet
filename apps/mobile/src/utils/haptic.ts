export function hapticSuccess() {
  if (navigator.vibrate) navigator.vibrate([30, 20, 30]);
}