const PRESETS = [
  { id: "720p", label: "720p", w: 1280, h: 720 },
  { id: "1080p", label: "1080p", w: 1920, h: 1080 },
  { id: "2k", label: "2K", w: 2560, h: 1440 },
  { id: "4k", label: "4K", w: 3840, h: 2160 },
  { id: "ultrawide", label: "1920×720", w: 1920, h: 720 },
  { id: "square", label: "1:1 1080", w: 1080, h: 1080 },
];

const canvas = document.getElementById("canvas");
const ctx = canvas.getContext("2d");
const fileInput = document.getElementById("fileInput");
const downloadBtn = document.getElementById("downloadBtn");
const dropzone = document.getElementById("dropzone");
const emptyState = document.getElementById("emptyState");
const presetsEl = document.getElementById("presets");
const customForm = document.getElementById("customForm");
const customW = document.getElementById("customW");
const customH = document.getElementById("customH");
const srcInfo = document.getElementById("srcInfo");
const cropInfo = document.getElementById("cropInfo");
const outInfo = document.getElementById("outInfo");
const jpegToggle = document.getElementById("jpegToggle");

const state = {
  image: null,
  target: { w: 1920, h: 1080, id: "1080p" },
  crop: { x: 0, y: 0, w: 0, h: 0 },
  view: { scale: 1, ox: 0, oy: 0 },
  drag: null,
};

function handleSize() {
  const r = dropzone.getBoundingClientRect();
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  canvas.width = Math.max(1, Math.floor(r.width * dpr));
  canvas.height = Math.max(1, Math.floor(r.height * dpr));
  canvas.style.width = `${r.width}px`;
  canvas.style.height = `${r.height}px`;
  layoutImage();
  draw();
}

function layoutImage() {
  if (!state.image) return;
  const pad = 24;
  const availW = canvas.width - pad * 2;
  const availH = canvas.height - pad * 2;
  const scale = Math.min(availW / state.image.width, availH / state.image.height);
  state.view.scale = scale;
  state.view.ox = (canvas.width - state.image.width * scale) / 2;
  state.view.oy = (canvas.height - state.image.height * scale) / 2;
  if (!state.crop.w) fitCrop();
  clampCrop();
}

function aspect() {
  return state.target.w / state.target.h;
}

function fitCrop() {
  if (!state.image) return;
  const a = aspect();
  let w = state.image.width;
  let h = w / a;
  if (h > state.image.height) {
    h = state.image.height;
    w = h * a;
  }
  state.crop = {
    x: (state.image.width - w) / 2,
    y: (state.image.height - h) / 2,
    w,
    h,
  };
}

function clampCrop() {
  if (!state.image) return;
  const img = state.image;
  const a = aspect();
  state.crop.w = Math.min(Math.max(32, state.crop.w), img.width);
  state.crop.h = state.crop.w / a;
  if (state.crop.h > img.height) {
    state.crop.h = img.height;
    state.crop.w = state.crop.h * a;
  }
  state.crop.x = Math.min(Math.max(0, state.crop.x), img.width - state.crop.w);
  state.crop.y = Math.min(Math.max(0, state.crop.y), img.height - state.crop.h);
}

function imgToCanvas(p) {
  return {
    x: state.view.ox + p.x * state.view.scale,
    y: state.view.oy + p.y * state.view.scale,
  };
}

function canvasToImg(p) {
  return {
    x: (p.x - state.view.ox) / state.view.scale,
    y: (p.y - state.view.oy) / state.view.scale,
  };
}

function eventPoint(e) {
  const r = canvas.getBoundingClientRect();
  const sx = canvas.width / r.width;
  const sy = canvas.height / r.height;
  return {
    x: (e.clientX - r.left) * sx,
    y: (e.clientY - r.top) * sy,
  };
}

function cropRectCanvas() {
  const p = imgToCanvas({ x: state.crop.x, y: state.crop.y });
  return {
    x: p.x,
    y: p.y,
    w: state.crop.w * state.view.scale,
    h: state.crop.h * state.view.scale,
  };
}

function handles(rect) {
  const s = 18;
  return {
    nw: { x: rect.x, y: rect.y, w: s, h: s },
    ne: { x: rect.x + rect.w - s, y: rect.y, w: s, h: s },
    sw: { x: rect.x, y: rect.y + rect.h - s, w: s, h: s },
    se: { x: rect.x + rect.w - s, y: rect.y + rect.h - s, w: s, h: s },
  };
}

function hit(rect, p) {
  return p.x >= rect.x && p.x <= rect.x + rect.w && p.y >= rect.y && p.y <= rect.y + rect.h;
}

function draw() {
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  if (!state.image) return;
  const { ox, oy, scale } = state.view;
  ctx.drawImage(state.image, ox, oy, state.image.width * scale, state.image.height * scale);

  const r = cropRectCanvas();
  ctx.save();
  ctx.fillStyle = "rgba(6, 8, 14, 0.55)";
  ctx.beginPath();
  ctx.rect(0, 0, canvas.width, canvas.height);
  ctx.rect(r.x, r.y, r.w, r.h);
  ctx.fill("evenodd");
  ctx.strokeStyle = "#6ee7c5";
  ctx.lineWidth = 3;
  ctx.strokeRect(r.x, r.y, r.w, r.h);

  ctx.strokeStyle = "rgba(255,255,255,0.35)";
  ctx.lineWidth = 1;
  for (let i = 1; i < 3; i++) {
    ctx.beginPath();
    ctx.moveTo(r.x + (r.w * i) / 3, r.y);
    ctx.lineTo(r.x + (r.w * i) / 3, r.y + r.h);
    ctx.moveTo(r.x, r.y + (r.h * i) / 3);
    ctx.lineTo(r.x + r.w, r.y + (r.h * i) / 3);
    ctx.stroke();
  }

  const hs = handles(r);
  ctx.fillStyle = "#e8edf7";
  Object.values(hs).forEach((h) => ctx.fillRect(h.x, h.y, h.w, h.h));
  ctx.restore();

  cropInfo.textContent = `${Math.round(state.crop.w)} × ${Math.round(state.crop.h)}`;
}

function setTarget(w, h, id) {
  state.target = { w, h, id };
  outInfo.textContent = `${w} × ${h}`;
  document.querySelectorAll(".presets button").forEach((b) => {
    b.classList.toggle("active", b.dataset.id === id);
  });
  fitCrop();
  draw();
}

function loadFile(file) {
  if (!file || !file.type.startsWith("image/")) return;
  const url = URL.createObjectURL(file);
  const img = new Image();
  img.onload = () => {
    URL.revokeObjectURL(url);
    state.image = img;
    state.crop = { x: 0, y: 0, w: 0, h: 0 };
    emptyState.hidden = true;
    downloadBtn.disabled = false;
    srcInfo.textContent = `${img.width} × ${img.height}`;
    layoutImage();
    draw();
  };
  img.src = url;
}

function onPointerDown(e) {
  if (!state.image) return;
  canvas.setPointerCapture(e.pointerId);
  const p = eventPoint(e);
  const r = cropRectCanvas();
  const hs = handles(r);
  for (const [name, box] of Object.entries(hs)) {
    if (hit(box, p)) {
      state.drag = { type: name, start: p, crop: { ...state.crop } };
      return;
    }
  }
  if (hit(r, p)) {
    state.drag = { type: "move", start: p, crop: { ...state.crop } };
  }
}

function onPointerMove(e) {
  if (!state.drag || !state.image) return;
  const p = eventPoint(e);
  const dx = (p.x - state.drag.start.x) / state.view.scale;
  const dy = (p.y - state.drag.start.y) / state.view.scale;
  const start = state.drag.crop;
  const a = aspect();
  if (state.drag.type === "move") {
    state.crop.x = start.x + dx;
    state.crop.y = start.y + dy;
  } else {
    let w = start.w;
    let h = start.h;
    let x = start.x;
    let y = start.y;
    if (state.drag.type.includes("e")) w = start.w + dx;
    if (state.drag.type.includes("w")) {
      w = start.w - dx;
      x = start.x + dx;
    }
    if (state.drag.type.includes("s")) h = start.h + dy;
    if (state.drag.type.includes("n")) {
      h = start.h - dy;
      y = start.y + dy;
    }
    w = Math.max(32, w);
    h = w / a;
    if (state.drag.type.includes("n")) y = start.y + start.h - h;
    if (state.drag.type.includes("w")) x = start.x + start.w - w;
    state.crop = { x, y, w, h };
  }
  clampCrop();
  draw();
}

function onPointerUp() {
  state.drag = null;
}

function download() {
  if (!state.image) return;
  const out = document.createElement("canvas");
  out.width = state.target.w;
  out.height = state.target.h;
  const octx = out.getContext("2d");
  octx.imageSmoothingQuality = "high";
  octx.drawImage(
    state.image,
    state.crop.x,
    state.crop.y,
    state.crop.w,
    state.crop.h,
    0,
    0,
    out.width,
    out.height
  );
  const jpeg = jpegToggle.checked;
  const mime = jpeg ? "image/jpeg" : "image/png";
  out.toBlob(
    (blob) => {
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `wallpaper-${state.target.w}x${state.target.h}.${jpeg ? "jpg" : "png"}`;
      a.click();
      URL.revokeObjectURL(a.href);
    },
    mime,
    0.92
  );
}

PRESETS.forEach((p) => {
  const b = document.createElement("button");
  b.type = "button";
  b.dataset.id = p.id;
  b.textContent = p.label;
  b.addEventListener("click", () => setTarget(p.w, p.h, p.id));
  presetsEl.appendChild(b);
});

fileInput.addEventListener("change", (e) => loadFile(e.target.files[0]));
downloadBtn.addEventListener("click", download);
customForm.addEventListener("submit", (e) => {
  e.preventDefault();
  const w = Number(customW.value);
  const h = Number(customH.value);
  if (!w || !h) return;
  setTarget(Math.round(w), Math.round(h), "custom");
});

["dragenter", "dragover"].forEach((ev) => {
  dropzone.addEventListener(ev, (e) => {
    e.preventDefault();
  });
});
dropzone.addEventListener("drop", (e) => {
  e.preventDefault();
  loadFile(e.dataTransfer.files[0]);
});

canvas.addEventListener("pointerdown", onPointerDown);
canvas.addEventListener("pointermove", onPointerMove);
canvas.addEventListener("pointerup", onPointerUp);
canvas.addEventListener("pointercancel", onPointerUp);
window.addEventListener("resize", handleSize);

setTarget(1920, 1080, "1080p");
handleSize();
