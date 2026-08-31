document.addEventListener('DOMContentLoaded', () => {
  const popup = document.getElementById('disclaimer-popup');
  const btn = document.getElementById('popup-accept-btn');

  if (popup && btn && !localStorage.getItem('disclaimerAccepted')) {
    popup.style.display = 'flex';
  }

  if (btn && popup) {
    btn.addEventListener('click', () => {
      localStorage.setItem('disclaimerAccepted', 'true');
      popup.style.display = 'none';
    });
  }
});