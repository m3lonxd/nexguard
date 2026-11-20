/* NexGuard: 3B küre taban katmanı (WebGL2).
   Ülke şekilleri sayfadaki SVG haritadan (world.json, 1000x500 eşdikdörtgen) okunur ve tek bir
   dokuya çizilir: R kanalı kara, G kanalı sınır çizgisi, B kanalı ülkenin bağlantı yoğunluğu.
   Uydu stili NASA Blue Marble görüntüsünü (kamu malı, yerel dosya) gri ya da renkli gösterir.
   Her karede tek tam ekran üçgen çizilir; küre piksel başına ters izdüşümle hesaplanır. */
(function () {
  "use strict";

  var VS = "#version 300 es\nvoid main(){ vec2 p=vec2(float((gl_VertexID<<1)&2),float(gl_VertexID&2)); gl_Position=vec4(p*2.-1.,0.,1.); }\n";
  var FS = [
    "#version 300 es",
    "precision highp float;",
    "uniform sampler2D uB; uniform sampler2D uS;",
    "uniform int uStyle; uniform float uColor, uHasSat, uDpr;",
    "uniform vec2 uSize; uniform vec3 uGlobe; uniform vec2 uRot;",
    "uniform vec3 uBg, uSea, uLand, uLine, uH1, uH2, uH3, uH4;",
    "out vec4 o;",
    "const float PI = 3.141592653589793;",
    "vec3 heat(float b) { return b < .375 ? uH1 : b < .625 ? uH2 : b < .875 ? uH3 : uH4; }",
    "vec3 shade(vec2 uv) {",
    "  vec4 t = texture(uB, uv); vec3 c;",
    "  if (uStyle == 2 && uHasSat > .5) {",
    "    vec3 s = texture(uS, uv).rgb;",
    "    float l = dot(s, vec3(.299, .587, .114));",
    "    c = mix(vec3(pow(l, 1.2) * .9), s * .95, uColor);",
    "    if (t.b > .1) c = mix(c, heat(t.b), .38);",
    "    c = mix(c, uLine * 1.6, t.g * .35);",
    "  } else {",
    "    c = mix(uSea, uLand, t.r);",
    "    if (t.b > .1) c = mix(c, heat(t.b), t.r);",
    "    c = mix(c, uLine, t.g);",
    "  }",
    "  return c;",
    "}",
    "void main() {",
    "  vec2 p = vec2(gl_FragCoord.x, uSize.y * uDpr - gl_FragCoord.y) / uDpr;",
    "  vec2 d = (p - uGlobe.xy) / uGlobe.z; float r2 = dot(d, d);",
    "  if (r2 > 1.) { float r = sqrt(r2); float a = smoothstep(1.05, 1., r) * .35;",
    "    o = vec4(uBg + (uStyle == 2 ? mix(vec3(.55), vec3(.42, .6, .9), uColor) : uLand * 1.4) * a, 1.); return; }",
    "  float x0 = d.x, y = -d.y, z = sqrt(1. - r2);",
    "  float cp = cos(uRot.y), sp = sin(uRot.y);",
    "  float y0 = y * cp + z * sp, z0 = -y * sp + z * cp;",
    "  float lat = asin(clamp(y0, -1., 1.)), lon = radians(uRot.x) + atan(x0, z0);",
    "  vec2 uv = vec2(fract((lon + PI) / (2. * PI)), (PI * .5 - lat) / PI);",
    "  vec3 c = shade(uv) * (.5 + .5 * pow(z, .55));",
    "  o = vec4(mix(uBg, c, smoothstep(0., .06, z)), 1.);",
    "}"].join("\n");

  function hex(v) {
    v = String(v).trim().replace("#", "");
    if (v.length === 3) v = v.split("").map(function (c) { return c + c; }).join("");
    var n = parseInt(v, 16);
    return isNaN(n) ? [0, 0, 0] : [(n >> 16 & 255) / 255, (n >> 8 & 255) / 255, (n & 255) / 255];
  }

  function create(canvas, opt) {
    var gl = canvas.getContext("webgl2", { alpha: false, antialias: false });
    if (!gl) return null;
    function compile(type, src) {
      var s = gl.createShader(type);
      gl.shaderSource(s, src); gl.compileShader(s);
      if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) throw new Error(gl.getShaderInfoLog(s));
      return s;
    }
    var prog;
    try {
      prog = gl.createProgram();
      gl.attachShader(prog, compile(gl.VERTEX_SHADER, VS));
      gl.attachShader(prog, compile(gl.FRAGMENT_SHADER, FS));
      gl.linkProgram(prog);
      if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) throw new Error(gl.getProgramInfoLog(prog));
    } catch (e) {
      if (window.console) console.error("kure: gölgelendirici", e);
      return null;
    }
    var U = {};
    ["uB", "uS", "uStyle", "uColor", "uHasSat", "uDpr", "uSize", "uGlobe", "uRot", "uBg", "uSea", "uLand", "uLine", "uH1", "uH2", "uH3", "uH4"]
      .forEach(function (n) { U[n] = gl.getUniformLocation(prog, n); });
    var vao = gl.createVertexArray();
    var maxTex = gl.getParameter(gl.MAX_TEXTURE_SIZE);
    var aniso = gl.getExtension("EXT_texture_filter_anisotropic");
    var colors = opt.colors;

    function upload(tex, unit, source) {
      gl.activeTexture(gl.TEXTURE0 + unit);
      gl.bindTexture(gl.TEXTURE_2D, tex);
      gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, source);
      gl.generateMipmap(gl.TEXTURE_2D);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR_MIPMAP_LINEAR);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.REPEAT);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
      if (aniso) gl.texParameterf(gl.TEXTURE_2D, aniso.TEXTURE_MAX_ANISOTROPY_EXT, Math.min(8, gl.getParameter(aniso.MAX_TEXTURE_MAX_ANISOTROPY_EXT)));
    }

    // ülke dokusu: Path2D ile SVG yolları, 1000x500 -> W x H
    var W = Math.min(2048, maxTex), H = W / 2;
    var cv = document.createElement("canvas");
    cv.width = W; cv.height = H;
    var cx = cv.getContext("2d");
    var shapes = (opt.paths || []).map(function (p) { return { cc: p.cc, path: new Path2D(p.d) }; });
    var tB = gl.createTexture();
    var heatKey = null;

    function paint(heat) {
      cx.setTransform(1, 0, 0, 1, 0, 0);
      cx.globalCompositeOperation = "source-over";
      cx.fillStyle = "#000"; cx.fillRect(0, 0, W, H);
      cx.setTransform(W / 1000, 0, 0, H / 500, 0, 0);
      shapes.forEach(function (s) {
        var lv = heat[s.cc] || 0;
        cx.fillStyle = "rgb(255,0," + Math.round(lv * 255) + ")";
        cx.fill(s.path);
      });
      cx.globalCompositeOperation = "lighter";
      cx.strokeStyle = "#0f0"; cx.lineWidth = 1000 / W * 1.1; cx.lineJoin = "round";
      shapes.forEach(function (s) { cx.stroke(s.path); });
      upload(tB, 0, cv);
    }
    paint({});

    var tS = null, sat = "none"; // none | loading | ready | error
    function loadSatellite() {
      if (sat !== "none") return;
      sat = "loading";
      var img = new Image();
      img.decoding = "async";
      img.onload = function () {
        try { tS = gl.createTexture(); upload(tS, 1, img); sat = "ready"; } catch (e) { sat = "error"; }
        opt.onChange();
      };
      img.onerror = function () { sat = "error"; opt.onChange(); };
      img.src = maxTex >= 8192 && window.innerWidth > 960 ? "/static/uydu/uydu-8192.jpg" : "/static/uydu/uydu-4096.jpg";
    }

    var lost = false;
    canvas.addEventListener("webglcontextlost", function (e) { e.preventDefault(); lost = true; });

    return {
      get satellite() { return sat; },
      loadSatellite: loadSatellite,
      // heat: { cc: 0..1 }; yalnız değişince yeniden çizilir
      setHeat: function (heat) {
        var key = Object.keys(heat).sort().map(function (k) { return k + heat[k]; }).join(",");
        if (key === heatKey) return;
        heatKey = key;
        paint(heat);
      },
      resize: function (w, h, dpr) { canvas.width = Math.floor(w * dpr); canvas.height = Math.floor(h * dpr); },
      draw: function (v) {
        if (lost) return;
        gl.viewport(0, 0, canvas.width, canvas.height);
        gl.useProgram(prog);
        gl.bindVertexArray(vao);
        gl.activeTexture(gl.TEXTURE0); gl.bindTexture(gl.TEXTURE_2D, tB);
        gl.activeTexture(gl.TEXTURE1); gl.bindTexture(gl.TEXTURE_2D, tS || tB);
        gl.uniform1i(U.uB, 0); gl.uniform1i(U.uS, 1);
        gl.uniform1i(U.uStyle, v.style === "uydu" ? 2 : 1);
        gl.uniform1f(U.uColor, v.color ? 1 : 0);
        gl.uniform1f(U.uHasSat, sat === "ready" ? 1 : 0);
        gl.uniform1f(U.uDpr, v.dpr);
        gl.uniform2f(U.uSize, v.W, v.H);
        gl.uniform3f(U.uGlobe, v.cx, v.cy, v.R);
        gl.uniform2f(U.uRot, v.lon0, v.pitch);
        ["bg", "sea", "land", "line", "h1", "h2", "h3", "h4"].forEach(function (k) {
          var c = hex(colors[k]);
          gl.uniform3f(U["u" + k.charAt(0).toUpperCase() + k.slice(1)], c[0], c[1], c[2]);
        });
        gl.drawArrays(gl.TRIANGLES, 0, 3);
      },
    };
  }

  window.NexKureGL = { create: create };
})();
