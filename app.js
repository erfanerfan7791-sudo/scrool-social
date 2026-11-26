
"use strict";

const $ = id => document.getElementById(id);

let mode = "login";
let token = localStorage.getItem("scrool_token") || "";
let currentUser = null;

function message(text) {
  $("authMessage").textContent = text || "";
}

function setMode(value) {
  mode = value;
  const register = value === "register";

  $("loginTab").classList.toggle("active", !register);
  $("registerTab").classList.toggle("active", register);
  $("authTitle").textContent = register ? "ساخت حساب جدید" : "ورود به حساب";
  $("authSubmit").textContent = register ? "ثبت‌نام" : "ورود";
  $("displayNameBox").classList.toggle("hidden", !register);
  message("");
}

$("loginTab").onclick = () => setMode("login");
$("registerTab").onclick = () => setMode("register");

async function api(url, options = {}) {
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {})
  };

  if (token) headers.Authorization = "Bearer " + token;

  const response = await fetch("/api" + url, {
    ...options,
    headers
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.error || "خطایی رخ داد");
  }

  return data;
}

$("authForm").onsubmit = async event => {
  event.preventDefault();

  const username = $("username").value.trim();
  const password = $("password").value;

  const body = {
    username,
    password
  };

  if (mode === "register") {
    body.displayName = $("displayName").value.trim();
  }

  try {
    $("authSubmit").disabled = true;
    message("لطفاً صبر کن...");

    const result = await api(
      mode === "register" ? "/register" : "/login",
      {
        method: "POST",
        body: JSON.stringify(body)
      }
    );

    token = result.token;
    localStorage.setItem("scrool_token", token);

    await loadUser();
    showApp();

  } catch (error) {
    message(error.message);
  } finally {
    $("authSubmit").disabled = false;
  }
};

async function loadUser() {
  const result = await api("/me");
  currentUser = result.user;

  $("profileName").textContent = currentUser.display_name;
  $("profileUsername").textContent = "@" + currentUser.username;
  $("profileBio").textContent = currentUser.bio || "";
  $("profileCreated").textContent =
    "عضویت: " + new Date(currentUser.created_at).toLocaleDateString("fa-IR");
}

function showApp() {
  $("authPage").classList.add("hidden");
  $("appPage").classList.remove("hidden");
}

function showAuth() {
  $("appPage").classList.add("hidden");
  $("authPage").classList.remove("hidden");
}

$("logoutBtn").onclick = () => {
  token = "";
  currentUser = null;
  localStorage.removeItem("scrool_token");
  showAuth();
};

$("themeToggle").onclick = () => {
  document.body.classList.toggle("light");

  localStorage.setItem(
    "scrool_theme",
    document.body.classList.contains("light") ? "light" : "dark"
  );
};

if (localStorage.getItem("scrool_theme") === "light") {
  document.body.classList.add("light");
}

document.querySelectorAll(".nav-btn").forEach(button => {
  button.onclick = () => {
    const page = button.dataset.page;

    document.querySelectorAll(".nav-btn").forEach(item => {
      item.classList.remove("active");
    });

    button.classList.add("active");

    ["home", "profile", "messages", "notifications"].forEach(name => {
      $(name + "Page").classList.toggle("hidden", name !== page);
    });
  };
});

// Posts
$("publishPost").onclick = async () => {
  alert("بخش انتشار پست در مرحله بعد به API متصل می‌شود.");
};

// Stories
$("addStoryBtn").onclick = () => {
  $("storyModal").classList.remove("hidden");
};

$("closeStory").onclick = () => {
  $("storyModal").classList.add("hidden");
};

$("submitStory").onclick = () => {
  $("storyMessage").textContent =
    "بخش آپلود استوری در مرحله بعد به سرور متصل می‌شود.";
};

async function init() {
  if (!token) return;

  try {
    await loadUser();
    showApp();
  } catch {
    token = "";
    localStorage.removeItem("scrool_token");
    showAuth();
  }
}

init();
