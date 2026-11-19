/* NexGuard paneli: harita taban katmanı (WebGL2).
   SINIR stili: Natural Earth ülke sınırları (sinirlar.js) 4096x2048 dokuya bir kez çizilir.
   UYDU stili: NASA Blue Marble (public domain) görüntüsü; gri tonlu ya da renkli.
   Her karede tek bir tam ekran üçgen çizilir: piksel başına ters izdüşüm (3B küre ya da
   2B eşdikdörtgen), bu yüzden yakınlaştırınca da maliyet sabit kalır.
   Saldırgan işaretleri, yaylar ve etiketler üstteki Canvas2D katmanındadır (harita.js). */
(function () {
  "use strict";
  const LAT_N = 84;

  const VS = "#version 300 es\nvoid main(){ vec2 p=vec2(float((gl_VertexID<<1)&2),float(gl_VertexID&2)); gl_Position=vec4(p*2.-1.,0.,1.); }\n";
  const FS = `#version 300 es
precision highp float;
uniform sampler2D uB;       // R: kara, G: sınır çizgisi
uniform sampler2D uS;       // uydu görüntüsü
uniform int uMode;          // 0: 2B, 1: 3B
uniform int uStyle;         // 1: sınır, 2: uydu
uniform float uColor;       // 0: gri, 1: renkli
uniform float uHasSat;
uniform vec2 uSize;         // CSS piksel
uniform float uDpr;
uniform vec3 uGlobe;        // cx, cy, R
uniform vec2 uRot;          // lon0 (derece), pitch (radyan)
uniform vec3 uFlat;         // k, ox, oy
out vec4 o;
const vec3 BG = vec3(6.0/255.0);
const float PI = 3.141592653589793;

vec3 shade(vec2 uv, float zoomPx) {
  vec4 b = texture(uB, uv);
  vec3 c;
  if (uStyle == 2 && uHasSat > 0.5) {
    vec3 s = texture(uS, uv).rgb;
    float l = dot(s, vec3(0.299, 0.587, 0.114));
    vec3 g = vec3(pow(l, 1.25) * 0.92);
    c = mix(g, s * 0.94, uColor);
    c += vec3(b.g) * mix(0.16, 0.10, uColor); // sınırlar uydu üstünde soluk
  } else {
    vec3 land = vec3(0.075, 0.075, 0.08);
    vec3 sea = vec3(0.028);
    c = mix(sea, land, b.r);
    c = mix(c, vec3(0.42, 0.42, 0.43), b.g * 0.9);
  }
  return c;
}

void main() {
  vec2 p = vec2(gl_FragCoord.x, uSize.y * uDpr - gl_FragCoord.y) / uDpr;
  if (uMode == 1) {
    vec2 d = (p - uGlobe.xy) / uGlobe.z;
    float r2 = dot(d, d);
    if (r2 > 1.0) {
      // ince atmosfer halkası
      float r = sqrt(r2);
      float a = smoothstep(1.06, 1.0, r) * 0.22;
      vec3 rim = uStyle == 2 ? mix(vec3(0.6), vec3(0.45, 0.62, 0.9), uColor) : vec3(0.55);
      o = vec4(BG + rim * a, 1.0);
      return;
    }
    float x0 = d.x, y = -d.y, z = sqrt(1.0 - r2);
    float cp = cos(uRot.y), sp = sin(uRot.y);
    float y0 = y * cp + z * sp, z0 = -y * sp + z * cp;
    float lat = asin(clamp(y0, -1.0, 1.0));
    float lon = radians(uRot.x) + atan(x0, z0);
    vec2 uv = vec2(fract((lon + PI) / (2.0 * PI)), (PI * 0.5 - lat) / PI);
    vec3 c = shade(uv, uGlobe.z);
    float limb = 0.42 + 0.58 * pow(z, 0.6);
    // kenara doğru hafif sis: kürenin hacmi okunur
    c = mix(BG, c * limb, smoothstep(0.0, 0.08, z));
    o = vec4(c + vec3(0.02) * (1.0 - z), 1.0);
  } else {
    float lon = (p.x - uFlat.y) / uFlat.x - 180.0;
    float lat = ${LAT_N.toFixed(1)} - (p.y - uFlat.z) / uFlat.x;
    if (lon < -180.0 || lon > 180.0 || lat < -90.0 || lat > 90.0) { o = vec4(BG, 1.0); return; }
    vec2 uv = vec2((lon + 180.0) / 360.0, (90.0 - lat) / 180.0);
    o = vec4(shade(uv, uFlat.x), 1.0);
  }
}
`;

  function create(canvas, opt) {
    const gl = canvas.getContext("webgl2", { alpha: false, antialias: false, premultipliedAlpha: false });
    if (!gl) return null;
    function compile(type, src) {
      const s = gl.createShader(type);
      gl.shaderSource(s, src); gl.compileShader(s);
      if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) throw new Error(gl.getShaderInfoLog(s));
      return s;
    }
    let prog;
    try {
      prog = gl.createProgram();
      gl.attachShader(prog, compile(gl.VERTEX_SHADER, VS));
      gl.attachShader(prog, compile(gl.FRAGMENT_SHADER, FS));
      gl.linkProgram(prog);
      if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) throw new Error(gl.getProgramInfoLog(prog));
    } catch (e) {
      if (window.console) console.error("harita: WebGL gölgelendirici", e);
      return null;
    }
    const U = {};
    ["uB", "uS", "uMode", "uStyle", "uColor", "uHasSat", "uSize", "uDpr", "uGlobe", "uRot", "uFlat"].forEach((n) => { U[n] = gl.getUniformLocation(prog, n); });
    const vao = gl.createVertexArray();
    const maxTex = gl.getParameter(gl.MAX_TEXTURE_SIZE);
    const aniso = gl.getExtension("EXT_texture_filter_anisotropic");

    function texture(unit, source) {
      const t = gl.createTexture();
      gl.activeTexture(gl.TEXTURE0 + unit);
      gl.bindTexture(gl.TEXTURE_2D, t);
      gl.pixelStorei(gl.UNPACK_FLIP_Y_WEBGL, false);
      gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, source);
      gl.generateMipmap(gl.TEXTURE_2D);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR_MIPMAP_LINEAR);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.REPEAT);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
      if (aniso) gl.texParameterf(gl.TEXTURE_2D, aniso.TEXTURE_MAX_ANISOTROPY_EXT, Math.min(8, gl.getParameter(aniso.MAX_TEXTURE_MAX_ANISOTROPY_EXT)));
      return t;
    }

    // sınır dokusu: kara dolgusu R, çizgiler G kanalında (toplamalı karışım)
    function buildBorders() {
      const W = Math.min(4096, maxTex), H = W / 2;
      const c = document.createElement("canvas");
      c.width = W; c.height = H;
      const x = c.getContext("2d");
      x.fillStyle = "#000"; x.fillRect(0, 0, W, H);
      const rings = window.NEXBORDERS || [];
      const P = (lon, lat) => [(lon / 100 + 180) / 360 * W, (90 - lat / 100) / 180 * H];
      x.beginPath();
      for (const r of rings) {
        for (let i = 0; i < r.length; i += 2) { const q = P(r[i], r[i + 1]); if (i === 0) x.moveTo(q[0], q[1]); else x.lineTo(q[0], q[1]); }
        x.closePath();
      }
      x.fillStyle = "#f00"; x.fill("evenodd");
      x.globalCompositeOperation = "lighter";
      x.strokeStyle = "#0f0"; x.lineWidth = Math.max(1, W / 2600); x.lineJoin = "round";
      x.stroke();
      return texture(0, c);
    }
    const tB = buildBorders();
    let tS = null, satState = "none"; // none | loading | ready | error

    function loadSatellite() {
      if (satState !== "none") return;
      satState = "loading";
      const big = maxTex >= 8192 && window.innerWidth > 960;
      const img = new Image();
      img.decoding = "async";
      img.onload = () => {
        try { tS = texture(1, img); satState = "ready"; } catch (e) { satState = "error"; }
        opt.onChange();
      };
      img.onerror = () => { satState = "error"; opt.onChange(); };
      img.src = big ? "/media/uydu-8192.jpg" : "/media/uydu-4096.jpg";
    }

    let lost = false;
    canvas.addEventListener("webglcontextlost", (e) => { e.preventDefault(); lost = true; });

    return {
      get satellite() { return satState; },
      loadSatellite,
      resize(W, H, dpr) { canvas.width = Math.floor(W * dpr); canvas.height = Math.floor(H * dpr); },
      // v: { mode, style, color, W, H, dpr, cx, cy, R, lon0, pitch, k, ox, oy }
      draw(v) {
        if (lost) return;
        gl.viewport(0, 0, canvas.width, canvas.height);
        gl.useProgram(prog);
        gl.bindVertexArray(vao);
        gl.activeTexture(gl.TEXTURE0); gl.bindTexture(gl.TEXTURE_2D, tB);
        gl.activeTexture(gl.TEXTURE1); gl.bindTexture(gl.TEXTURE_2D, tS || tB);
        gl.uniform1i(U.uB, 0); gl.uniform1i(U.uS, 1);
        gl.uniform1i(U.uMode, v.mode === "3d" ? 1 : 0);
        gl.uniform1i(U.uStyle, v.style === "uydu" ? 2 : 1);
        gl.uniform1f(U.uColor, v.color ? 1 : 0);
        gl.uniform1f(U.uHasSat, satState === "ready" ? 1 : 0);
        gl.uniform2f(U.uSize, v.W, v.H);
        gl.uniform1f(U.uDpr, v.dpr);
        gl.uniform3f(U.uGlobe, v.cx, v.cy, v.R);
        gl.uniform2f(U.uRot, v.lon0, v.pitch);
        gl.uniform3f(U.uFlat, v.k, v.ox, v.oy);
        gl.drawArrays(gl.TRIANGLES, 0, 3);
      },
    };
  }

  window.NexGlobe = { create };
})();
