const DESKTOP_BREAKPOINT = 668;

let _width = $state(typeof window !== "undefined" ? window.innerWidth : Infinity);

if (typeof window !== "undefined") {
  const handleResize = () => {
    _width = window.innerWidth;
  };

  window.addEventListener("resize", handleResize, { passive: true });

  if (import.meta.hot) {
    import.meta.hot.dispose(() => {
      window.removeEventListener("resize", handleResize);
    });
  }
}

export const viewport = {
  get isDesktop() {
    return _width > DESKTOP_BREAKPOINT;
  },
};
