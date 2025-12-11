<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Crajy Boys — Home</title>
  <style>
    /* simple gaming/neon style */
    @keyframes glow {
      0% { text-shadow: 0 0 6px rgba(255,255,255,0.15); }
      50% { text-shadow: 0 0 18px rgba(0,255,200,0.45); }
      100% { text-shadow: 0 0 6px rgba(255,255,255,0.15); }
    }
    body{
      margin:0;
      font-family: "Segoe UI", Roboto, sans-serif;
      background:
        radial-gradient(circle at 10% 10%, rgba(0,255,200,0.06), transparent 8%),
        linear-gradient(120deg, #0b0f1a, #071022 60%);
      color:#e6f7ff;
      min-height:100vh;
    }
    /* top-right logo */
    #logo {
      position: fixed;
      top: 12px;
      right: 12px;
      width:72px;
      height:72px;
      object-fit:contain;
      border-radius:10px;
      box-shadow: 0 6px 18px rgba(0,0,0,0.7);
      background: linear-gradient(135deg, rgba(255,255,255,0.03), rgba(0,0,0,0.08));
      z-index: 50;
    }

    header{
      text-align:center;
      padding:40px 20px 10px;
    }
    h1.title{
      margin:0;
      font-size:48px;
      letter-spacing:2px;
      font-weight:800;
      color: #9fffe0;
      display:inline-block;
      padding:10px 22px;
      border-radius:14px;
      background: linear-gradient(90deg, rgba(255,255,255,0.02), rgba(0,0,0,0.05));
      transform: skewX(-6deg);
      animation: glow 3s ease-in-out infinite;
      box-shadow: 0 10px 40px rgba(0,255,200,0.06), inset 0 -6px 10px rgba(0,0,0,0.2);
      text-transform: uppercase;
    }

    /* column of page links (centered under title) */
    .nav-column{
      margin: 26px auto 12px;
      width:220px;
      text-align:center;
      display:flex;
      flex-direction:column;
      gap:16px;
    }
    .nav-column a{
      color:#d8fff4;
      text-decoration:none;
      font-weight:700;
      padding:8px 12px;
      border-radius:10px;
      transition: all .18s ease;
      background: linear-gradient(180deg, rgba(255,255,255,0.01), rgba(0,0,0,0.05));
      box-shadow: 0 8px 20px rgba(0,0,0,0.5);
    }
    .nav-column a:hover{
      transform: translateY(-4px) scale(1.03);
      box-shadow: 0 18px 40px rgba(0,255,200,0.08);
      color: #001f17;
      background: linear-gradient(90deg,#9fffe0,#6ee6c6);
    }

    main.container{
      display:flex;
      justify-content:center;
      margin-top:24px;
      padding: 20px;
    }
    .welcome{
      max-width:760px;
      background: rgba(255,255,255,0.02);
      border-radius:14px;
      padding:22px;
      box-shadow: 0 8px 30px rgba(0,0,0,0.6);
      border: 1px solid rgba(255,255,255,0.03);
    }
    .welcome h2{
      margin:0 0 12px 0;
      font-size:22px;
      color:#bfffe9;
    }
    .quote{
      font-size:16px;
      line-height:1.5;
      opacity:0.95;
    }

    footer{
      text-align:center;
      color:#9fdcd0;
      margin:32px 0 40px;
      opacity:0.9;
    }

    @media (max-width:600px){
      h1.title{ font-size:32px; }
      .nav-column{ width:85%; }
      #logo{ width:56px; height:56px; }
    }
  </style>
</head>
<body>
  <!-- put your logo file 'logo.png' in same folder; replace as needed -->
  <img id="logo" src="logo.png" alt="Crajy Boys Logo" onerror="this.style.display='none'">

  <header>
    <h1 class="title">Crajy Boys</h1>

    <div class="nav-column" aria-label="main links">
      <!-- exact filenames as you asked -->
      <a href="aboutus.html">About Us</a>
      <a href="members.html">Members</a>
      <a href="YT channel.html">Yt Channel</a>
    </div>
  </header>

  <main class="container">
    <section class="welcome">
      <h2>Welcome, player!</h2>
      <p class="quote">
        Step into Crajy Boys — where clutch plays, epic fails and non-stop gaming energy collide.
        Pull up a chair, pick a game, and let's make the scoreboard jealous. 🔥
      </p>
      <p class="quote" style="margin-top:12px;">
        Tip: Click <strong>About Us</strong> to learn more, <strong>Members</strong> to join the crew, or <strong>Yt Channel</strong> to watch our latest clips.
      </p>
    </section>
  </main>

  <footer>
    Designed with a gamer vibe — Crajy Boys ©
  </footer>
</body>
</html>



