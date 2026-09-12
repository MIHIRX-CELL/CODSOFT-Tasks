/* =========================================================
   PHISHGUARD - CODSOFT TASK 2
   Phishing Awareness Training
   ========================================================= */

const TOTAL_MODULES = 9;

const moduleData = [
    {
        id: 2,
        title: "What is Phishing?",
        desc: "Understand phishing attacks and their objectives.",
        icon: "🎣"
    },
    {
        id: 3,
        title: "Suspicious Email Detector",
        desc: "Identify phishing indicators inside an email.",
        icon: "📧"
    },
    {
        id: 4,
        title: "Fake Login Pages",
        desc: "Learn how credential harvesting pages work.",
        icon: "🔑"
    },
    {
        id: 5,
        title: "Fraudulent Websites",
        desc: "Detect suspicious shopping websites.",
        icon: "🌐"
    },
    {
        id: 6,
        title: "Social Engineering",
        desc: "Identify psychological manipulation techniques.",
        icon: "🧠"
    },
    {
        id: 7,
        title: "Case Studies",
        desc: "Study realistic phishing scenarios.",
        icon: "📚"
    },
    {
        id: 8,
        title: "Security Tips",
        desc: "Build safer online habits.",
        icon: "🔐"
    },
    {
        id: 9,
        title: "I Got Phished",
        desc: "Learn what to do after an incident.",
        icon: "🚨"
    },
    {
        id: 10,
        title: "Final Quiz",
        desc: "Test your phishing awareness knowledge.",
        icon: "🏆"
    }
];

/* =========================================================
   PROGRESS
   ========================================================= */

let completedModules = JSON.parse(
    localStorage.getItem("phishguard_completed") || "[]"
);

function updateProgress() {

    const completed = completedModules.length;

    const percent = Math.round(
        (completed / TOTAL_MODULES) * 100
    );

    const fill = document.getElementById("progressFill");
    const text = document.getElementById("progressText");
    const completedText = document.getElementById("completedText");

    if (fill) {
        fill.style.width = percent + "%";
    }

    if (text) {
        text.textContent = percent + "%";
    }

    if (completedText) {
        completedText.textContent =
            completed + " of " + TOTAL_MODULES + " modules completed";
    }

    renderModuleCards();
}

/* =========================================================
   DASHBOARD CARDS
   ========================================================= */

function renderModuleCards() {

    const container = document.getElementById("moduleCards");

    if (!container) return;

    container.innerHTML = "";

    moduleData.forEach(module => {

        const done = completedModules.includes(module.id);

        const card = document.createElement("div");

        card.className =
            "module-card " + (done ? "completed" : "");

        card.onclick = function () {
            openModule("module" + module.id);
        };

        card.innerHTML = `
            ${done ? '<div class="done">✓</div>' : ''}
            <div class="num">MODULE ${String(module.id).padStart(2, "0")}</div>
            <h3>${module.icon} ${module.title}</h3>
            <p>${module.desc}</p>
        `;

        container.appendChild(card);
    });
}

/* =========================================================
   NAVIGATION
   ========================================================= */

function openModule(moduleId) {

    document.querySelectorAll(".screen").forEach(screen => {
        screen.classList.remove("active");
    });

    const target = document.getElementById(moduleId);

    if (!target) {
        console.error("Module not found:", moduleId);
        return;
    }

    target.classList.add("active");

    document.querySelectorAll(".nav-item").forEach(item => {
        item.classList.remove("active");
    });

    if (moduleId === "home") {

        const homeButton =
            document.querySelector(
                '.nav-item[onclick*="openModule(\'home\')"]'
            );

        if (homeButton) {
            homeButton.classList.add("active");
        }

    } else {

        const navButton =
            document.querySelector(
                `.nav-item[onclick*="'${moduleId}'"]`
            );

        if (navButton) {
            navButton.classList.add("active");
        }
    }

    window.scrollTo({
        top: 0,
        behavior: "smooth"
    });

    if (moduleId === "module6") {
        initializeScenarios();
    }

    if (moduleId === "module10") {
        renderQuiz();
    }
}

/* =========================================================
   COMPLETE MODULE
   ========================================================= */

function completeModule(number) {

    if (!completedModules.includes(number)) {

        completedModules.push(number);

        completedModules.sort((a, b) => a - b);

        localStorage.setItem(
            "phishguard_completed",
            JSON.stringify(completedModules)
        );
    }

    updateProgress();

    alert(
        "Module " +
        number +
        " completed successfully! ✓"
    );
}

/* =========================================================
   MODULE 3 - EMAIL
   ========================================================= */

function emailLinkWarning() {

    alert(
        "Training warning:\n\n" +
        "Never click unexpected verification links before checking " +
        "the sender and destination."
    );
}

function analyzeEmail() {

    const selected = [
        ...document.querySelectorAll(
            '#module3 input[type="checkbox"]:checked'
        )
    ].map(input => input.value);

    const correct = [
        "sender",
        "urgency",
        "verification",
        "action"
    ];

    const result = document.getElementById("emailResult");

    const hasAllCorrect =
        correct.every(item => selected.includes(item));

    const hasWrong =
        selected.includes("greeting");

    if (hasAllCorrect && !hasWrong) {

        result.className =
            "result-box show result-success";

        result.innerHTML = `
            <strong>✓ PHISHING DETECTED</strong><br><br>
            Correct. The sender domain is suspicious, the message
            creates urgency, requests verification and pushes the
            recipient to act immediately.
        `;

    } else {

        result.className =
            "result-box show result-error";

        result.innerHTML = `
            <strong>✗ Not quite.</strong><br><br>
            Select the core indicators: suspicious sender,
            urgency, unexpected verification request and pressure
            to take immediate action. A generic greeting alone is
            not enough to classify a message as phishing.
        `;
    }
}

/* =========================================================
   MODULE 4 - LOGIN
   ========================================================= */

function analyzeLogin() {

    const selected = [
        ...document.querySelectorAll(
            '#module4 input[type="checkbox"]:checked'
        )
    ].map(input => input.value);

    const correct = [
        "domain",
        "login",
        "link"
    ];

    const wrong = selected.includes("https");

    const result = document.getElementById("loginResult");

    const allCorrect =
        correct.every(item => selected.includes(item));

    if (allCorrect && !wrong) {

        result.className =
            "result-box show result-success";

        result.innerHTML = `
            <strong>✓ GOOD ANALYSIS</strong><br><br>
            The suspicious domain, unexpected login request and
            possible unverified link are important warning signs.
            Remember: HTTPS encrypts a connection, but it does
            not automatically prove that a website is legitimate.
        `;

    } else {

        result.className =
            "result-box show result-error";

        result.innerHTML = `
            <strong>✗ Review the indicators.</strong><br><br>
            HTTPS alone does not make a website trustworthy.
            Focus on the domain, context and how you reached the page.
        `;
    }
}

/* =========================================================
   MODULE 5 - WEBSITE
   ========================================================= */

function shopButtonWarning() {

    alert(
        "Training simulation:\n\n" +
        "Before buying, verify the seller, website and payment process."
    );
}

function analyzeSite() {

    const selected = [
        ...document.querySelectorAll(
            '#module5 input[type="checkbox"]:checked'
        )
    ].map(input => input.value);

    const correct = [
        "price",
        "urgency",
        "seller",
        "payment"
    ];

    const wrong = selected.includes("cheap");

    const result = document.getElementById("siteResult");

    const allCorrect =
        correct.every(item => selected.includes(item));

    if (allCorrect && !wrong) {

        result.className =
            "result-box show result-success";

        result.innerHTML = `
            <strong>✓ SUSPICIOUS WEBSITE DETECTED</strong><br><br>
            The unrealistic price, urgency, unknown seller and
            possible payment pressure are strong warning signs.
            A low price by itself does not automatically prove fraud.
        `;

    } else {

        result.className =
            "result-box show result-error";

        result.innerHTML = `
            <strong>✗ Review your selection.</strong><br><br>
            Look for unrealistic pricing, artificial urgency,
            unknown sellers and unusual payment pressure.
        `;
    }
}

/* =========================================================
   MODULE 6 - SOCIAL ENGINEERING
   ========================================================= */

const scenarios = [

    {
        text:
            "Your account will be blocked in 10 minutes. Verify immediately.",
        options: [
            "Urgency",
            "Curiosity",
            "Reward",
            "Technical Support"
        ],
        answer: "Urgency"
    },

    {
        text:
            "I am your IT administrator. Give me your OTP so I can fix your account.",
        options: [
            "Reward",
            "Authority + Impersonation",
            "Curiosity",
            "Urgency only"
        ],
        answer: "Authority + Impersonation"
    },

    {
        text:
            "Congratulations! You have won ₹1,00,000. Claim your reward now.",
        options: [
            "Authority",
            "Curiosity",
            "Reward",
            "Fear"
        ],
        answer: "Reward"
    },

    {
        text:
            "Confidential document about you attached. Open it immediately.",
        options: [
            "Curiosity",
            "Authority",
            "Reward",
            "Technical Support"
        ],
        answer: "Curiosity"
    }
];

let currentScenario = 0;
let scenarioScore = 0;
let scenarioAnswered = false;

function initializeScenarios() {

    currentScenario = 0;
    scenarioScore = 0;
    scenarioAnswered = false;

    renderScenario();

    const score =
        document.getElementById("scenarioScore");

    if (score) {
        score.style.display = "none";
    }
}

function renderScenario() {

    const area =
        document.getElementById("scenarioArea");

    if (!area) return;

    if (currentScenario >= scenarios.length) {

        showScenarioScore();
        return;
    }

    const scenario = scenarios[currentScenario];

    scenarioAnswered = false;

    area.innerHTML = `
        <div class="scenario-box">

            <div class="scenario-count">
                SCENARIO ${currentScenario + 1} OF ${scenarios.length}
            </div>

            <div class="scenario-message">
                “${scenario.text}”
            </div>

            <div class="scenario-options">
                ${scenario.options.map(option => `
                    <button
                        class="scenario-option"
                        onclick="answerScenario('${option.replace(/'/g, "\\'")}')">
                        ${option}
                    </button>
                `).join("")}
            </div>

            <div id="scenarioFeedback"
                 class="scenario-feedback">
            </div>

        </div>
    `;
}

function answerScenario(selected) {

    if (scenarioAnswered) return;

    scenarioAnswered = true;

    const scenario = scenarios[currentScenario];

    const feedback =
        document.getElementById("scenarioFeedback");

    if (selected === scenario.answer) {

        scenarioScore++;

        feedback.style.display = "block";
        feedback.style.background =
            "rgba(33,230,163,.08)";
        feedback.style.border =
            "1px solid rgba(33,230,163,.2)";
        feedback.style.color =
            "var(--green)";

        feedback.innerHTML =
            "✓ Correct! " + scenario.answer +
            " is the manipulation technique.";

    } else {

        feedback.style.display = "block";
        feedback.style.background =
            "rgba(255,92,112,.08)";
        feedback.style.border =
            "1px solid rgba(255,92,112,.2)";
        feedback.style.color =
            "#ff8796";

        feedback.innerHTML =
            "✗ Incorrect. The correct answer is <strong>" +
            scenario.answer +
            "</strong>.";
    }

    setTimeout(() => {

        currentScenario++;

        renderScenario();

    }, 1100);
}

function showScenarioScore() {

    const area =
        document.getElementById("scenarioArea");

    const score =
        document.getElementById("scenarioScore");

    area.innerHTML = `
        <div class="scenario-box">
            <h2>Scenario Lab Complete</h2>
            <p>
                You scored
                <strong>${scenarioScore}/${scenarios.length}</strong>.
            </p>
        </div>
    `;

    score.style.display = "block";

    if (scenarioScore >= 3) {

        score.innerHTML =
            "✓ Good job! You understand the major social engineering techniques.";

    } else {

        score.innerHTML =
            "Review the scenarios once more and focus on urgency, authority, rewards and curiosity.";

    }
}

/* =========================================================
   MODULE 10 - FINAL QUIZ
   ========================================================= */

const quizQuestions = [

    {
        question:
            "Which is a common warning sign of a phishing message?",
        options: [
            "Unexpected urgency",
            "A normal conversation with a known person",
            "A saved bookmark",
            "An offline document"
        ],
        answer: 0
    },

    {
        question:
            "Does HTTPS automatically prove that a website is legitimate?",
        options: [
            "Yes, always",
            "No, HTTPS alone does not prove legitimacy",
            "Only on mobile devices",
            "Only when the website has images"
        ],
        answer: 1
    },

    {
        question:
            "Your manager urgently asks you to make a payment to a new bank account. What should you do?",
        options: [
            "Pay immediately",
            "Reply with your OTP",
            "Verify the request through a separate trusted channel",
            "Forward it to everyone"
        ],
        answer: 2
    },

    {
        question:
            "What should you do with an OTP received for your account?",
        options: [
            "Share it with anyone claiming to be support",
            "Post it online",
            "Never share it with another person",
            "Send it by email"
        ],
        answer: 2
    },

    {
        question:
            "You receive an unexpected suspicious link. What is the safest action?",
        options: [
            "Click it quickly",
            "Verify independently and avoid the suspicious link",
            "Enter your password first",
            "Forward it to a friend"
        ],
        answer: 1
    },

    {
        question:
            "You entered your password on a suspected phishing page. What should you do first?",
        options: [
            "Ignore it",
            "Change the password through the legitimate service and secure reused accounts",
            "Share the password with support",
            "Delete your browser"
        ],
        answer: 1
    }
];

function renderQuiz() {

    const container =
        document.getElementById("quizContainer");

    if (!container) return;

    container.innerHTML = "";

    quizQuestions.forEach((question, index) => {

        const div =
            document.createElement("div");

        div.className = "quiz-question";

        div.innerHTML = `
            <div class="question-number">
                QUESTION ${index + 1}
            </div>

            <h2>${question.question}</h2>

            <div class="quiz-options">

                ${question.options.map((option, optionIndex) => `
                    <label class="quiz-option">
                        <input
                            type="radio"
                            name="question${index}"
                            value="${optionIndex}">
                        ${option}
                    </label>
                `).join("")}

            </div>
        `;

        container.appendChild(div);
    });
}

function submitQuiz() {

    let score = 0;

    quizQuestions.forEach((question, index) => {

        const selected =
            document.querySelector(
                `input[name="question${index}"]:checked`
            );

        if (
            selected &&
            Number(selected.value) === question.answer
        ) {
            score++;
        }
    });

    const percentage =
        Math.round(
            (score / quizQuestions.length) * 100
        );

    const result =
        document.getElementById("quizResult");

    result.classList.add("show");

    if (percentage >= 70) {

        result.className =
            "quiz-result show quiz-pass";

        result.innerHTML = `
            <h2>🎉 Training Completed</h2>
            <p>
                Your score is
                <strong>${score}/${quizQuestions.length}</strong>
                (${percentage}%).
            </p>
            <p>
                You passed the phishing awareness assessment.
            </p>
        `;

        completeModule(10);

    } else {

        result.className =
            "quiz-result show quiz-fail";

        result.innerHTML = `
            <h2>Keep Learning</h2>
            <p>
                Your score is
                <strong>${score}/${quizQuestions.length}</strong>
                (${percentage}%).
            </p>
            <p>
                You need at least 70% to pass.
                Review the modules and retake the quiz.
            </p>
        `;
    }
}

function resetQuiz() {

    document.querySelectorAll(
        '#quizContainer input[type="radio"]'
    ).forEach(input => {
        input.checked = false;
    });

    const result =
        document.getElementById("quizResult");

    result.className = "quiz-result";
    result.innerHTML = "";

    window.scrollTo({
        top: 0,
        behavior: "smooth"
    });
}

/* =========================================================
   INITIAL LOAD
   ========================================================= */

document.addEventListener("DOMContentLoaded", function () {

    updateProgress();

    renderQuiz();

    renderModuleCards();

});
