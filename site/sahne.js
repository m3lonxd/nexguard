/* NexGuard: tek sürekli nokta bulutu sahnesi (saf WebGL2).
   Nokta bulutu bir kez üretilir; kaydırma ilerlemesi g (0..1) kamerayı ve GPU'daki morph
   uniform'larını sürer. Zamana değil kaydırmaya bağlıdır: geri kaydırınca geri oynar.
   Telemetri verisi örnektir: kayıt satırları README senaryosundan, saatlik histogram örnek değerdir. */
(function () {
  "use strict";
  var TAU = Math.PI * 2;
  function mulberry32(a) { return function () { a |= 0; a = a + 0x6D2B79F5 | 0; var t = Math.imul(a ^ a >>> 15, 1 | a); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; }; }
  function makeNoise(seed) {
    var r = mulberry32(seed), g = new Float32Array(65536), i; for (i = 0; i < 65536; i++) g[i] = r();
    return function (x, y) {
      var xi = Math.floor(x), yi = Math.floor(y), xf = x - xi, yf = y - yi, u = xf * xf * (3 - 2 * xf), v = yf * yf * (3 - 2 * yf);
      var a = g[((yi & 255) << 8) | (xi & 255)], b = g[((yi & 255) << 8) | ((xi + 1) & 255)], c = g[(((yi + 1) & 255) << 8) | (xi & 255)], d = g[(((yi + 1) & 255) << 8) | ((xi + 1) & 255)];
      return a + (b - a) * u + (c - a) * v + (a - b - c + d) * u * v;
    };
  }
  function clamp(x, a, b) { return x < a ? a : x > b ? b : x; }
  function sm(a, b, x) { var t = clamp((x - a) / (b - a), 0, 1); return t * t * (3 - 2 * t); }
  function mix(a, b, t) { return a + (b - a) * t; }

  /* ---------- arazi ---------- */
  var nz = makeNoise(9);
  var PK = [ // x, z, genlik, sx, sz
    [-0.18, 0.03, 0.52, 0.15, 0.17], [-0.92, 0.10, 0.13, 0.13, 0.15], [0.55, -0.10, 0.15, 0.13, 0.13],
    [0.95, -0.28, 0.11, 0.12, 0.14], [0.22, 0.30, 0.08, 0.15, 0.09], [-0.52, -0.40, 0.13, 0.18, 0.11],
    [0.1, 0.0, 0.09, 0.75, 0.40]];
  var BLK = { x: -0.18, z: 0.03, y: 0.9 }, THR = 0.4;
  function ridged(x, z) {
    var a = 0, amp = 0.55, f = 3.0;
    for (var o = 0; o < 5; o++) { var v = 1 - Math.abs(2 * nz(x * f + o * 17.3, z * f + o * 31.7) - 1); v *= v; a += v * amp; amp *= 0.5; f *= 2.1; }
    return a;
  }
  function H(x, z) {
    var e = 0, i, p;
    for (i = 0; i < PK.length; i++) { p = PK[i]; e += p[2] * Math.exp(-((x - p[0]) * (x - p[0]) / (2 * p[3] * p[3]) + (z - p[1]) * (z - p[1]) / (2 * p[4] * p[4]))); }
    var r = ridged(x, z), edge = 1 - sm(0.95, 1.25, Math.abs(x));
    return (e * (0.35 + 1.25 * r) + 0.03 * r) * edge;
  }
  function peakW(x, z) { return Math.exp(-((x - BLK.x) * (x - BLK.x) / (2 * 0.13 * 0.13) + (z - BLK.z) * (z - BLK.z) / (2 * 0.17 * 0.17))); }

  var HIST = [2, 1, 1, 2, 3, 5, 4, 3, 2, 2, 3, 2, 2, 1, 2, 3, 6, 9, 7, 5, 3, 2, 2, 1]; // örnek
  var HG = { x0: -0.45, bw: 0.04, gap: 0.008, yb: 0.0, hh: 0.55, z: 0.0 };
  var LOG = [
    "10:00:01 sshd[1234]: Failed password for root from 203.0.113.7 port 40001",
    "10:00:02 sshd[1234]: Failed password for root from 203.0.113.7 port 40002",
    "10:00:03 sshd[1234]: Failed password for root from 203.0.113.7 port 40003",
    "[...]",
    "10:00:05 sshd[1234]: Failed password for root from 203.0.113.7 port 40005"];

  /* ---------- nokta deposu ---------- */
  var STR = 12, CAP = 150000, D, N;
  function add(ax, ay, az, bx, by, bz, b0, b1, sz, ph, w, ty) {
    var o = N * STR; D[o] = ax; D[o + 1] = ay; D[o + 2] = az; D[o + 3] = bx; D[o + 4] = by; D[o + 5] = bz;
    D[o + 6] = b0; D[o + 7] = b1; D[o + 8] = sz; D[o + 9] = ph; D[o + 10] = w; D[o + 11] = ty; N++;
  }
  // tipler: 0 arazi, 1 zemin, 2 hayalet, 3 eşik düzlemi, 4 Tux, 5 histogram, 6 ızgara, 7 kayıt metni

  function buildCloud(tuxData, textPts) {
    D = new Float32Array(CAP * STR); N = 0;
    var r = mulberry32(5), i, j, k;
    // ana tepenin gerçek zirvesi ve eşik yüksekliği
    var best = 0, bx = BLK.x, bz = BLK.z;
    for (i = -40; i <= 40; i++) for (j = -40; j <= 40; j++) { var x = BLK.x + i * 0.004, z = BLK.z + j * 0.004, h = H(x, z); if (h > best) { best = h; bx = x; bz = z; } }
    BLK.x = bx; BLK.z = bz; BLK.y = best;
    for (i = 0; i < 160; i++) for (j = 0; j < 100; j++) { var x2 = -1.15 + i / 159 * 2.3, z2 = -0.55 + j / 99 * 1.1; if (peakW(x2, z2) < 0.003) mo = Math.max(mo, H(x2, z2)); }
    THR = clamp(mo * 1.12 + 0.03, 0.3, 0.52);
    var hmax = best;

    // histogram hedefleri (önce üretilir, arazi noktalarına dağıtılır)
    var HT = [], bx0, h, v, n, kk, yy, top, b;
    for (h = 0; h < 24; h++) {
      v = HIST[h]; n = Math.round(v * 110); var hgt = v / 10 * HG.hh;
      for (kk = 0; kk < n; kk++) {
        yy = r() * hgt; top = 1 - yy / hgt;
        b = 0.30 + 0.38 * Math.pow(1 - top, 1.5) + (top < 0.2 ? 0.3 : 0) + (yy > hgt - 0.012 ? 0.2 : 0);
        HT.push([HG.x0 + h * (HG.bw + HG.gap) + r() * HG.bw, HG.yb + yy, HG.z + (r() - 0.5) * 0.01, Math.min(1, b)]);
      }
    }
    for (i = HT.length - 1; i > 0; i--) { j = Math.floor(r() * (i + 1)); var tmp = HT[i]; HT[i] = HT[j]; HT[j] = tmp; }
    var hp = 0;
    function terrainPoint(x, z, extra, ty) {
      var hh = H(x, z), e = 0.004;
      var dz = (H(x, z + e) - H(x, z - e)) / (2 * e), facing = clamp(0.45 + 1.6 * dz, 0, 1), hn = Math.min(1, hh / hmax);
      var b = Math.min(1, (0.12 + 1.0 * Math.pow(hn, 1.1)) * (0.55 + 0.6 * facing) + extra);
      b *= (1 - sm(0.8, 1.15, Math.abs(x))) * (0.3 + 0.7 * sm(-0.55, -0.2, z));
      var w = peakW(x, z), ph = r();
      var bxx = x * 1.3, byy = -0.03 - r() * 0.2, bzz = z * 1.3, b1 = 0.04 * r();
      if (hp < HT.length && r() < 0.14) { var t = HT[hp++]; bxx = t[0]; byy = t[1]; bzz = t[2]; b1 = t[3]; }
      add(x, hh, z, bxx, byy, bzz, b, b1, r(), ph, w, ty);
    }
    var NX = 330, NZ = 210, X0 = -1.15, X1 = 1.15, Z0 = -0.55, Z1 = 0.6;
    for (i = 0; i < NX; i++) for (j = 0; j < NZ; j++) terrainPoint(X0 + (i + r()) / NX * (X1 - X0), Z0 + (j + r()) / NZ * (Z1 - Z0), 0, 0);
    for (k = 0, n = 0; n < 20000 && k < 800000; k++) {
      var cx = X0 + r() * (X1 - X0), cz = Z0 + r() * (Z1 - Z0), ch = H(cx, cz);
      if (r() < Math.pow(ch / hmax, 3.2)) { terrainPoint(cx, cz, 0, 0); n++; }
    }
    // histogramın kalanı: zemin ölçüm gürültüsünden yükselir
    for (; hp < HT.length; hp++) { var t2 = HT[hp]; add(t2[0] * 1.4, -0.05 - r() * 0.2, (r() - 0.5) * 1.5, t2[0], t2[1], t2[2], 0, t2[3], r(), r(), 0, 5); }
    // zemin ölçüm gürültüsü
    for (i = 0; i < 8000; i++) {
      var fx = -1.7 + r() * 3.4, fz = -0.9 + r() * 1.9, fy = -0.01 - Math.pow(r(), 1.6) * 0.32, fall = 1 - (-fy - 0.01) / 0.32, fb = (0.14 + 0.3 * r()) * fall;
      add(fx, fy, fz, fx, fy, fz, fb, fb, r(), r(), 0, 1);
    }
    // hayalet: yükselmiş tepenin soluk kopyası (çökünce görünür)
    for (k = 0, n = 0; n < 6000 && k < 400000; k++) {
      var gx = BLK.x - 0.4 + r() * 0.8, gz = BLK.z - 0.45 + r() * 0.9;
      if (r() < peakW(gx, gz) * 0.9) { var gy = H(gx, gz); add(gx, gy, gz, gx, gy, gz, 0.14 + 0.1 * (gy / hmax), 0, r(), r(), 0, 2); n++; }
    }
    // eşik düzlemi: soluk noktalı
    for (i = 0; i < 150; i++) for (j = 0; j < 34; j++) {
      if ((i + j) % 2) continue;
      var px = -1.25 + i / 149 * 2.5, pz = -0.6 + j / 33 * 1.2; add(px, THR, pz, px, THR, pz, 0.55, 0, 0, r(), 0, 3);
    }
    // histogram ızgarası (%20 aralıklı noktalı çizgiler)
    var gw = 24 * (HG.bw + HG.gap);
    for (var g = 0; g <= 5; g++) for (i = 0; i < 170; i++) { var gxx = HG.x0 - 0.02 + i / 169 * (gw + 0.03), gyy = HG.yb + g / 5 * HG.hh; add(gxx, gyy, HG.z, gxx, gyy, HG.z, 0, g === 0 ? 0.55 : 0.22, 0, r(), 0, 6); }
    // Tux: aynı malzeme
    if (tuxData) {
      var w2 = tuxData.w, h2 = tuxData.h, d = tuxData.d, TH = 0.66, kk2 = TH / h2, rr = mulberry32(41);
      for (var py = 0; py < h2; py++) for (var pxl = 0; pxl < w2; pxl++) {
        var ii = (py * w2 + pxl) * 4; if (d[ii + 3] < 128) continue;
        var L = (0.3 * d[ii] + 0.59 * d[ii + 1] + 0.11 * d[ii + 2]) / 255, nn = Math.floor(0.10 + 0.42 * L + rr());
        for (var q = 0; q < nn; q++) {
          var u = (pxl + rr() - w2 / 2) * kk2, vv = (h2 - (py + rr())) * kk2, rel = -(L - 0.08) * 0.07 + (rr() - 0.5) * 0.02;
          var bt = Math.min(1, (0.10 + 0.9 * Math.pow(L, 1.15)) * (0.85 + 0.3 * rr()) * 0.55), ph2 = rr();
          add(1.12 + u, 0.02 + vv, 0.40 + rel, -0.85 + u, 0.02 + vv, 0.0 + rel, bt, bt, rr(), ph2, 0, 4);
        }
      }
    }
    // kayıt satırları: nokta metin, arazinin ön sırasına dönüşür
    if (textPts) {
      var S = 0.0025;
      for (i = 0; i < textPts.length; i += 3) {
        var tx = (textPts[i] - 400) * S, ty = 0.36 + (80 - textPts[i + 1]) * S, ord = textPts[i + 2];
        var fz2 = 0.58 + (r() - 0.5) * 0.02, fx = clamp(tx, -1.1, 1.1);
        add(tx, ty, 0.78 + (r() - 0.5) * 0.004, fx, H(fx, fz2) * 0.62 * 0 + H(fx, fz2), fz2, 0.9, 0.9, r(), ord, 0, 7);
      }
    }
  }

  /* ---------- gölgelendiriciler ---------- */
  var VS = "#version 300 es\nprecision highp float;\n" +
    "in vec3 aA; in vec3 aB; in vec2 aBri; in vec4 aM;\n" +
    "uniform mat4 uVP; uniform vec3 uCam; uniform float uFocus, uScale, uTime, uDrift, uScan, uLogm, uTerr, uPlane, uRise, uCol, uSc, uDim, uTuxDim;\n" +
    "out float vR;\n" +
    "out float vB;\n" +
    "float hs(float x){ return fract(sin(x*127.1+311.7)*43758.5453); }\n" +
    "float sm(float a,float b,float x){ float t=clamp((x-a)/(b-a),0.,1.); return t*t*(3.-2.*t); }\n" +
    "void main(){\n" +
    " float ty=aM.w, ph=aM.y, w=aM.z, sz=aM.x;\n" +
    " float r1=hs(ph), r2=hs(ph+3.1), r3=hs(ph+7.7);\n" +
    " vec3 A=aA, B=aB, P; float bri=aBri.x, vis=1., fl=1.;\n" +
    " float key=clamp((0.8-aA.z)/1.5,0.,1.);\n" +
    " if(ty>6.5){\n" +
    "  float e=sm(0.,1.,uLogm); P=mix(A,B,e); P.y+=sin(e*3.14159)*0.1*(r1-.3);\n" +
    "  vis=step(ph,uScan); fl=1.+0.6*(1.-sm(0.,0.05,uScan-ph)); bri*=1.-sm(0.8,1.,uLogm);\n" +
    " } else {\n" +
    "  if(ty<0.5){\n" +
    "   A.y*=1.-w*(1.-uRise)*0.62;\n" +
    "   float c=clamp(uCol*1.8-ph*0.8,0.,1.); c=c*c*(3.-2.*c)*sm(0.03,0.35,w);\n" +
    "   A=mix(A,vec3(A.x+(r1-.5)*0.10,-0.01-r2*0.12,A.z+(r3-.5)*0.10),c);\n" +
    "  }\n" +
    "  float s=clamp(uSc*1.35-ph*0.35,0.,1.);\n" +
    "  vec3 S=vec3(A.x*1.35+(r1-.5)*0.9,-0.03-r2*0.22,A.z*1.4+(r3-.5)*0.9);\n" +
    "  if(ty>3.5&&ty<4.5) S=A+(vec3(r1,r2,r3)-.5)*vec3(0.5,0.5,0.3);\n" +
    "  if(ty>0.5&&ty<1.5) S=A;\n" +
    "  float e1=sm(0.,1.,s*2.), e2=sm(0.,1.,s*2.-1.);\n" +
    "  P= s<0.5 ? mix(A,S,e1) : mix(S,B,e2);\n" +
    "  bri=mix(aBri.x,aBri.y,sm(0.35,0.95,s));\n" +
    "  if(ty<1.5||(ty>3.5&&ty<4.5)){ float rv=uTerr*1.1; vis=sm(key,key+0.05,rv); fl=1.+0.4*(1.-sm(0.,0.06,rv-key))*vis; }\n" +
    "  else if(ty<2.5) vis=sm(0.,0.4,uCol);\n" +
    "  else if(ty<3.5){ float kx=(aA.x+1.25)/2.5; vis=sm(kx,kx+0.06,uPlane*1.08); }\n" +
    " }\n" +
    " P+=uDrift*0.003*vec3(sin(uTime*.9+ph*40.),cos(uTime*.7+ph*23.),sin(uTime*.8+ph*31.));\n" +
    " float dist=length(P-uCam);\n" +
    " float fog=mix(1.,0.4,sm(0.,2.4,dist-uFocus));\n" +
    " float dm = (ty>3.5&&ty<4.5) ? uTuxDim : uDim;\n" +
    " vB=bri*vis*fl*fog*dm;\n" +
    " if(vB<0.004){ gl_Position=vec4(2.,2.,2.,1.); gl_PointSize=0.; return; }\n" +
    " gl_Position=uVP*vec4(P,1.);\n" +
    // ince noktalar: boyut 3.4 px ile sınırlı; 1 px altına düşen nokta parlaklığını alanına göre verir
    " float ps=(0.7+sz*1.1)*uScale/dist; vR=clamp(ps,0.,1.);\n" +
    " gl_PointSize=clamp(ps,1.,3.4);\n" +
    "}\n";
  // uGain: HDR hedefte doğrusal enerji, yedek yolda doğrudan parlaklık
  var FS = "#version 300 es\nprecision mediump float;\nin float vB; in float vR; uniform float uGain; out vec4 o;\n" +
    "void main(){ vec2 d=gl_PointCoord-.5; float r=length(d)*2.; if(r>1.) discard;\n" +
    " float a=1.-smoothstep(0.55,1.,r); float e=pow(clamp(vB,0.,2.),0.9)*a*uGain*mix(0.5,1.,vR);\n" +
    " o=vec4(vec3(e),1.); }\n";
  // tonemap: üst üste binen noktalar beyaza kesilmek yerine yumuşakça doygunlaşır
  var TVS = "#version 300 es\nvoid main(){ vec2 p=vec2(float((gl_VertexID<<1)&2),float(gl_VertexID&2)); gl_Position=vec4(p*2.-1.,0.,1.); }\n";
  var TFS = "#version 300 es\nprecision highp float;\nuniform sampler2D uT; uniform float uExp; out vec4 o;\n" +
    "void main(){ vec3 x=texelFetch(uT,ivec2(gl_FragCoord.xy),0).rgb; vec3 v=1.-exp(-x*uExp);\n" +
    " o=vec4(vec3(6./255.)+v*(1.-6./255.),1.); }\n";
  var GAIN_HDR = 0.85, GAIN_LDR = 0.5, EXPO = 1.25;

  /* ---------- kamera ---------- */
  var KEY = [ // g, konum, hedef, fov(derece)
    [0.00, [0.35, 1.05, 3.2], [0.0, 0.20, 0.0], 34],
    [0.07, [0.15, 0.95, 3.1], [0.0, 0.24, 0.0], 34],
    [0.13, [0.0, 0.40, 3.15], [0.0, 0.34, 0.75], 34],
    [0.26, [0.0, 0.42, 2.15], [0.0, 0.20, 0.10], 36],
    [0.34, [0.85, 0.55, 1.95], [0.0, 0.30, 0.0], 36],
    [0.50, [0.45, 0.70, 1.95], [-0.15, 0.60, 0.03], 36],
    [0.60, [0.28, 0.72, 1.70], [-0.18, 0.66, 0.03], 34],
    [0.72, [0.22, 0.60, 1.95], [-0.18, 0.50, 0.03], 34],
    [0.90, [0.0, 0.30, 2.7], [0.0, 0.28, 0.0], 34],
    [1.00, [0.0, 0.30, 2.7], [0.0, 0.28, 0.0], 34]];
  var SH = [ // g, yatay kayma (+ sağa), dikey kayma (+ yukarı): sahne metin bloğunun karşı yanında kalır
    [0.00, 0.30, 0.04], [0.08, 0.26, 0.10], [0.14, 0.06, 0.16], [0.30, 0.06, 0.12], [0.37, -0.28, 0.10], [0.50, -0.28, 0.08],
    [0.57, 0.26, 0.04], [0.72, 0.26, 0.04], [0.80, -0.14, 0.02], [1.00, -0.14, 0.02]];
  function shAt(g, c) {
    var i = 0; while (i < SH.length - 2 && g > SH[i + 1][0]) i++;
    var a = SH[i], b = SH[i + 1], u = sm(a[0], b[0], g), x = mix(a[1], b[1], u), y = mix(a[2], b[2], u);
    var e = sm(0, 1, c); return [mix(x, 0.34, e), mix(y, 0.0, e)];
  }
  var CLOSE = { pos: [-0.30, 0.34, 2.05], tgt: [-0.85, 0.34, 0.0], fov: 34 };
  function camAt(g, c, t, drift) {
    var i = 0; while (i < KEY.length - 2 && g > KEY[i + 1][0]) i++;
    var a = KEY[i], b = KEY[i + 1], u = sm(a[0], b[0], g), p = [], q = [], k;
    for (k = 0; k < 3; k++) { p[k] = mix(a[1][k], b[1][k], u); q[k] = mix(a[2][k], b[2][k], u); }
    var f = mix(a[3], b[3], u);
    if (c > 0) { var e = sm(0, 1, c); for (k = 0; k < 3; k++) { p[k] = mix(p[k], CLOSE.pos[k], e); q[k] = mix(q[k], CLOSE.tgt[k], e); } }
    if (drift) { var yaw = 0.02 * Math.sin(t * 0.09), dx = p[0] - q[0], dz = p[2] - q[2]; p[0] = q[0] + dx * Math.cos(yaw) + dz * Math.sin(yaw); p[2] = q[2] - dx * Math.sin(yaw) + dz * Math.cos(yaw); }
    return { pos: p, tgt: q, fov: f };
  }
  function lookAt(e, t) {
    var zx = e[0] - t[0], zy = e[1] - t[1], zz = e[2] - t[2], l = Math.hypot(zx, zy, zz); zx /= l; zy /= l; zz /= l;
    var xx = zz, xy = 0, xz = -zx; l = Math.hypot(xx, xz); xx /= l; xz /= l;
    var yx = zy * xz - zz * xy, yy = zz * xx - zx * xz, yz = zx * xy - zy * xx;
    return [xx, yx, zx, 0, xy, yy, zy, 0, xz, yz, zz, 0, -(xx * e[0] + xy * e[1] + xz * e[2]), -(yx * e[0] + yy * e[1] + yz * e[2]), -(zx * e[0] + zy * e[1] + zz * e[2]), 1];
  }
  function persp(th, asp, n, f, shx, shy) {
    return [1 / (th * asp), 0, 0, 0, 0, 1 / th, 0, 0, -shx, -shy, -(f + n) / (f - n), -1, 0, 0, -2 * f * n / (f - n), 0];
  }
  function mul(a, b) { var o = new Array(16), i, j, k; for (i = 0; i < 4; i++) for (j = 0; j < 4; j++) { var s = 0; for (k = 0; k < 4; k++) s += a[k * 4 + j] * b[i * 4 + k]; o[i * 4 + j] = s; } return o; }

  /* ---------- sahne durumu (g -> uniform) ---------- */
  function state(g) {
    return { scan: sm(0.10, 0.17, g), logm: sm(0.17, 0.245, g), rise: sm(0.28, 0.40, g), plane: sm(0.34, 0.42, g), col: sm(0.64, 0.72, g), sc: sm(0.74, 0.88, g) };
  }

  /* ---------- çalışma zamanı ---------- */
  var lastT = 0, mo = 0, G = {}, gl, prog, vao, U = {}, cvs, cssW = 1, cssH = 1, dpr = 1, ready = false, raf = 0;
  var tgtG = 0, curG = 0, tgtC = 0, tgtDim = 1, azHareket = false, lastVP = null, fps = 0, fpsN = 0, fpsT = 0, onReady = null, running = false;
  var ov = {}, scr = {}, hdr = null;

  function scramble(el, text, key, t0, now) {
    if (!el) return;
    var f = Math.floor((now - t0) * 30), out = "", i, G16 = "0123456789ABCDEF";
    if (azHareket || f >= text.length * 1 + 8) { if (el.textContent !== text) el.textContent = text; return; }
    for (i = 0; i < text.length; i++) {
      if (text[i] === " " || i < f - 8) out += text[i];
      else out += G16[Math.floor(Math.abs(Math.sin((i + 1) * 12.9898 + f * 78.233) * 43758.5453) % 1 * 16)];
    }
    el.textContent = out;
  }
  function project(w) {
    if (!lastVP) return null;
    var m = lastVP, x = w[0], y = w[1], z = w[2], cw = m[3] * x + m[7] * y + m[11] * z + m[15];
    if (cw <= 0) return null;
    return [(m[0] * x + m[4] * y + m[8] * z + m[12]) / cw * 0.5 * cssW + cssW / 2, (1 - (m[1] * x + m[5] * y + m[9] * z + m[13]) / cw) * 0.5 * cssH];
  }
  function place(el, p, ox, oy) { el.style.transform = "translate(" + Math.round(p[0] + (ox || 0)) + "px," + Math.round(p[1] + (oy || 0)) + "px)"; }
  function vis(el, o) { var v = o > 0.01 ? "1" : "0"; if (el.style.opacity !== String(Math.round(o * 100) / 100)) el.style.opacity = String(Math.round(o * 100) / 100); el.style.visibility = o > 0.01 ? "visible" : "hidden"; return v; }

  function overlays(g, st, now) {
    if (!ov.root) return;
    var c, p;
    // eşik etiketi
    if (ov.esik) { p = project([-1.22, THR, 0.55]); c = sm(0.38, 0.42, g) * (1 - sm(0.72, 0.76, g)); if (p && c > 0) { place(ov.esik, p, -4, -22); vis(ov.esik, c); } else vis(ov.esik, 0); }
    // tepe: zirve yüksekliği
    var cy = BLK.y * (1 - (1 - st.rise) * 0.62), cc = clamp(st.col * 1.8 - 0.4, 0, 1); cc = cc * cc * (3 - 2 * cc); cy = mix(cy, 0.0, cc);
    var cp = project([BLK.x, cy, BLK.z]);
    if (ov.cagri) {
      c = sm(0.43, 0.46, g) * (1 - sm(0.54, 0.57, g));
      if (cp && c > 0) { place(ov.cagri, cp, 0, 0); vis(ov.cagri, c); } else vis(ov.cagri, 0);
    }
    if (ov.kilit) {
      c = sm(0.555, 0.585, g) * (1 - sm(0.74, 0.78, g));
      if (cp && c > 0) {
        var k = 1 + 0.5 * (1 - sm(0.555, 0.62, g)); ov.kilit.style.setProperty("--k", k.toFixed(3));
        place(ov.kilit, cp, 0, 0); vis(ov.kilit, c);
        if (ov.yaz) { if (g > 0.6) { if (!scr.kilit) scr.kilit = now; scramble(ov.yaz, "nftables · TTL 1 sa", "k", scr.kilit, now); } else { scr.kilit = 0; ov.yaz.textContent = ""; } }
      } else { vis(ov.kilit, 0); scr.kilit = 0; }
    }
    if (ov.hist) {
      c = sm(0.90, 0.95, g);
      if (c > 0.01) {
        var gw = 24 * (HG.bw + HG.gap), pt = project([HG.x0, HG.yb + HG.hh + 0.05, HG.z]);
        if (pt) { vis(ov.hist, c * tgtDim * (1 - 0.8 * tgtC)); ov.hist.style.setProperty("--x", Math.round(pt[0]) + "px"); ov.hist.style.setProperty("--y", Math.round(pt[1]) + "px");
          var ticks = ov.hist.querySelectorAll("[data-t]"), i, q;
          for (i = 0; i < ticks.length; i++) { var hr = +ticks[i].getAttribute("data-t"); q = project([HG.x0 + hr * (HG.bw + HG.gap) + (hr === 24 ? -HG.gap : HG.bw / 2), HG.yb - 0.03, HG.z]); if (q) ticks[i].style.transform = "translate(" + Math.round(q[0] - pt[0]) + "px," + Math.round(q[1] - pt[1]) + "px)"; } }
      } else vis(ov.hist, 0);
    }
  }

  function draw(now) {
    var g = curG, c = tgtC, st = state(g);
    var cam = camAt(g, c, now, !azHareket), th = Math.tan(cam.fov * Math.PI / 360), asp = cssW / cssH;
    var wid = Math.max(1, 1.45 / asp); th *= wid;
    var sh = shAt(g, c);
    var P = persp(th, asp, 0.05, 20, sh[0], sh[1]), V = lookAt(cam.pos, cam.tgt), VP = mul(P, V);
    lastVP = VP;
    var f = Math.hypot(cam.pos[0] - cam.tgt[0], cam.pos[1] - cam.tgt[1], cam.pos[2] - cam.tgt[2]);
    gl.viewport(0, 0, cvs.width, cvs.height);
    if (hdr) { gl.bindFramebuffer(gl.FRAMEBUFFER, hdr.fb); gl.clearColor(0, 0, 0, 0); }
    else gl.clearColor(6 / 255, 6 / 255, 6 / 255, 1);
    gl.clear(gl.COLOR_BUFFER_BIT);
    gl.enable(gl.BLEND);
    gl.useProgram(prog); gl.bindVertexArray(vao);
    gl.uniform1f(U.uGain, hdr ? GAIN_HDR : GAIN_LDR);
    gl.uniformMatrix4fv(U.uVP, false, new Float32Array(VP));
    gl.uniform3f(U.uCam, cam.pos[0], cam.pos[1], cam.pos[2]);
    gl.uniform1f(U.uFocus, f);
    gl.uniform1f(U.uScale, cvs.height / (2 * th) * 0.0049);
    gl.uniform1f(U.uTime, azHareket ? 0 : now); gl.uniform1f(U.uDrift, azHareket ? 0 : 1);
    gl.uniform1f(U.uScan, st.scan); gl.uniform1f(U.uLogm, st.logm); gl.uniform1f(U.uTerr, 1);
    gl.uniform1f(U.uPlane, st.plane); gl.uniform1f(U.uRise, st.rise); gl.uniform1f(U.uCol, st.col); gl.uniform1f(U.uSc, st.sc);
    var dim = tgtDim * (1 - 0.65 * c);
    gl.uniform1f(U.uDim, dim); gl.uniform1f(U.uTuxDim, mix(dim, 1, c * c));
    gl.drawArrays(gl.POINTS, 0, N);
    if (hdr) {
      gl.bindFramebuffer(gl.FRAMEBUFFER, null); gl.disable(gl.BLEND);
      gl.useProgram(hdr.prog); gl.bindVertexArray(hdr.vao);
      gl.activeTexture(gl.TEXTURE0); gl.bindTexture(gl.TEXTURE_2D, hdr.tex);
      gl.uniform1i(hdr.uT, 0); gl.uniform1f(hdr.uExp, EXPO);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
    }
    overlays(g, st, now);
  }

  function frame(ts) {
    raf = requestAnimationFrame(frame);
    if (document.hidden || !ready) return;
    var now = ts / 1000;
    var dt = Math.min(0.25, now - lastT); lastT = now;
    if (azHareket) curG = tgtG; else { var d = tgtG - curG; curG = Math.abs(d) < 0.0004 ? tgtG : curG + d * (1 - Math.exp(-dt * 4)); }
    G.g = curG;
    draw(now);
    fpsN++; if (now - fpsT >= 1) { fps = fpsN / (now - fpsT); fpsN = 0; fpsT = now; G.fps = fps; }
  }

  function resize() {
    var r = cvs.getBoundingClientRect(); cssW = Math.max(2, r.width); cssH = Math.max(2, r.height);
    dpr = Math.min(2, window.devicePixelRatio || 1);
    cvs.width = Math.round(cssW * dpr); cvs.height = Math.round(cssH * dpr);
    if (hdr) sizeHdr();
    if (ready) draw(performance.now() / 1000);
  }

  /* ---------- HDR hedefi (EXT_color_buffer_float yoksa doğrudan çizime düşer) ---------- */
  function makeHdr() {
    if (!gl.getExtension("EXT_color_buffer_float")) return null;
    try {
      var p = gl.createProgram(); gl.attachShader(p, compile(gl.VERTEX_SHADER, TVS)); gl.attachShader(p, compile(gl.FRAGMENT_SHADER, TFS)); gl.linkProgram(p);
      if (!gl.getProgramParameter(p, gl.LINK_STATUS)) return null;
      var t = gl.createTexture(); gl.bindTexture(gl.TEXTURE_2D, t);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST); gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE); gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
      return { prog: p, tex: t, fb: gl.createFramebuffer(), vao: gl.createVertexArray(), uT: gl.getUniformLocation(p, "uT"), uExp: gl.getUniformLocation(p, "uExp") };
    } catch (e) { return null; }
  }
  function sizeHdr() {
    gl.bindTexture(gl.TEXTURE_2D, hdr.tex);
    gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA16F, cvs.width, cvs.height, 0, gl.RGBA, gl.HALF_FLOAT, null);
    gl.bindFramebuffer(gl.FRAMEBUFFER, hdr.fb);
    gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, hdr.tex, 0);
    var ok = gl.checkFramebufferStatus(gl.FRAMEBUFFER) === gl.FRAMEBUFFER_COMPLETE;
    gl.bindFramebuffer(gl.FRAMEBUFFER, null);
    if (!ok) hdr = null;
  }

  function compile(type, src) { var s = gl.createShader(type); gl.shaderSource(s, src); gl.compileShader(s); if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) throw new Error(gl.getShaderInfoLog(s)); return s; }

  function textPoints() {
    var c = document.createElement("canvas"); c.width = 800; c.height = 170;
    var x = c.getContext("2d", { willReadFrequently: true }), i, r = mulberry32(77);
    x.fillStyle = "#fff"; x.textBaseline = "top"; x.font = "500 17px 'JetBrains Mono', ui-monospace, Menlo, Consolas, monospace";
    for (i = 0; i < LOG.length; i++) x.fillText(LOG[i], 24, 12 + i * 30);
    var d = x.getImageData(0, 0, 800, 170).data, out = [], px, py;
    for (py = 0; py < 170; py++) for (px = 0; px < 800; px++) {
      if (d[(py * 800 + px) * 4 + 3] > 90 && r() < 0.9) out.push(px, py, (Math.floor((py - 12) / 30) + px / 800 * 0.9) / LOG.length);
    }
    return out;
  }
  function loadTux() {
    return new Promise(function (ok) {
      var im = new Image();
      im.onload = function () { try { var c = document.createElement("canvas"); c.width = im.naturalWidth; c.height = im.naturalHeight; var x = c.getContext("2d", { willReadFrequently: true }); x.drawImage(im, 0, 0); ok({ w: c.width, h: c.height, d: x.getImageData(0, 0, c.width, c.height).data }); } catch (e) { ok(null); } };
      im.onerror = function () { ok(null); };
      im.src = G.tuxUrl;
    });
  }
  function fontsReady() {
    if (!document.fonts || !document.fonts.load) return Promise.resolve();
    return Promise.race([document.fonts.load("500 17px 'JetBrains Mono'"), new Promise(function (r) { setTimeout(r, 1500); })]).catch(function () {});
  }

  G.init = function (canvas, opts) {
    cvs = canvas; opts = opts || {}; G.tuxUrl = opts.tux || "media/tux.png";
    azHareket = !!opts.azHareket;
    gl = cvs.getContext("webgl2", { alpha: false, antialias: false, powerPreference: "high-performance", preserveDrawingBuffer: !!opts.koru });
    if (!gl) return false;
    try {
      prog = gl.createProgram(); gl.attachShader(prog, compile(gl.VERTEX_SHADER, VS)); gl.attachShader(prog, compile(gl.FRAGMENT_SHADER, FS)); gl.linkProgram(prog);
      if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) throw new Error(gl.getProgramInfoLog(prog));
    } catch (e) { if (window.console) console.error(e); return false; }
    ["uVP", "uCam", "uFocus", "uScale", "uTime", "uDrift", "uScan", "uLogm", "uTerr", "uPlane", "uRise", "uCol", "uSc", "uDim", "uTuxDim", "uGain"].forEach(function (n) { U[n] = gl.getUniformLocation(prog, n); });
    gl.enable(gl.BLEND); gl.blendFunc(gl.ONE, gl.ONE); gl.disable(gl.DEPTH_TEST);
    hdr = opts.hdr === false ? null : makeHdr(); G.hdr = !!hdr;
    cvs.addEventListener("webglcontextlost", function (e) { e.preventDefault(); ready = false; if (opts.kayip) opts.kayip(); });
    ov.root = opts.hud; if (ov.root) { ov.esik = ov.root.querySelector("[data-o=esik]"); ov.cagri = ov.root.querySelector("[data-o=cagri]"); ov.kilit = ov.root.querySelector("[data-o=kilit]"); ov.yaz = ov.root.querySelector("[data-o=yaz]"); ov.hist = ov.root.querySelector("[data-o=hist]"); }
    resize(); window.addEventListener("resize", resize);
    Promise.all([loadTux(), fontsReady()]).then(function (r) {
      buildCloud(r[0], textPoints());
      var buf = gl.createBuffer(); vao = gl.createVertexArray(); gl.bindVertexArray(vao); gl.bindBuffer(gl.ARRAY_BUFFER, buf);
      gl.bufferData(gl.ARRAY_BUFFER, D.subarray(0, N * STR), gl.STATIC_DRAW);
      var sz = STR * 4; function at(name, n, off) { var l = gl.getAttribLocation(prog, name); gl.enableVertexAttribArray(l); gl.vertexAttribPointer(l, n, gl.FLOAT, false, sz, off * 4); }
      at("aA", 3, 0); at("aB", 3, 3); at("aBri", 2, 6); at("aM", 4, 8);
      D = null; ready = true; G.H = H; G.count = N; G.thr = THR; G.mo = mo; G.top = BLK.y;
      if (!raf) raf = requestAnimationFrame(frame);
      if (opts.hazir) opts.hazir();
    });
    return true;
  };
  G.set = function (g, c, dim, snap) { tgtG = clamp(g, 0, 1); tgtC = clamp(c, 0, 1); tgtDim = dim; if (snap) curG = tgtG; };
  G.duraklat = function () { if (raf) { cancelAnimationFrame(raf); raf = 0; } };
  G.surdur = function () { if (!raf) raf = requestAnimationFrame(frame); };
  G.yenidenBoyutla = resize;
  window.NexScene = G;
})();
