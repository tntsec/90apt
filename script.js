// ===== DOM 元素 =====
const navbar = document.querySelector('.navbar');
const hamburger = document.querySelector('.hamburger');
const navMenu = document.querySelector('.nav-menu');
const navLinks = document.querySelectorAll('.nav-link');
const statNumbers = document.querySelectorAll('.stat-number');
const tutorialCards = document.querySelectorAll('.tutorial-card');
const featureItems = document.querySelectorAll('.feature-item');
const productCards = document.querySelectorAll('.products-card');
const backToTop = document.getElementById('backToTop');

const userStat = document.querySelector('.stat-number[data-stat="users"]');
if (userStat) {
    const baseCount = parseInt(userStat.getAttribute('data-target'), 10) || 0;
    const storageKey = '90apt-user-count';
    // 兜底：storage 不可用时直接用页面里写死的基准值
    let nextCount = baseCount + 1;

    try {
        const stored = parseInt(localStorage.getItem(storageKey), 10);
        // 以页面基准值为下限 —— 老访客本地残留的旧基数（如 55246）不会把数字拽回去
        const current = Math.max(Number.isFinite(stored) ? stored : 0, baseCount);
        // 同一次会话内反复刷新不重复计数，避免把数字刷虚
        const countedThisSession = sessionStorage.getItem(storageKey) === '1';
        nextCount = current + (countedThisSession ? 0 : 1);

        sessionStorage.setItem(storageKey, '1');
        localStorage.setItem(storageKey, String(nextCount));
    } catch (e) {
        // 隐私模式或 file:// 下读写 storage 可能抛异常，
        // 不捕获的话整个脚本会中断，后面的导航高亮、动画全部失效
    }

    userStat.setAttribute('data-target', String(nextCount));
}

// ===== 按帧合并执行 =====
// 滚动事件在高刷屏或触控板上每秒可触发上百次，同一帧内逐个执行会造成大量重复计算。
// 用 rAF 合并后，每帧最多只跑一次。
function rafThrottle(fn) {
    let queued = false;
    return function () {
        if (queued) return;
        queued = true;
        requestAnimationFrame(() => {
            queued = false;
            fn();
        });
    };
}

// ===== 移动端菜单切换 =====
// 汉堡按钮是 <button>，除了视觉状态还要同步 aria-expanded，
// 否则读屏用户无从判断菜单当前是开着还是关着。
function setMenuOpen(open) {
    hamburger.classList.toggle('active', open);
    navMenu.classList.toggle('active', open);
    hamburger.setAttribute('aria-expanded', String(open));
    document.body.style.overflow = open ? 'hidden' : '';
}

if (hamburger && navMenu) {
    hamburger.addEventListener('click', () => {
        setMenuOpen(!navMenu.classList.contains('active'));
    });

    // 点击链接关闭菜单
    navLinks.forEach(link => {
        link.addEventListener('click', () => setMenuOpen(false));
    });
}

// ===== 平滑滚动 =====
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    });
});

// ===== 数字滚动动画 =====
// 统一用不带千分位的纯数字：四个统计项并排展示时，66,666 会和 4 / 90 / 100 的
// 写法割裂。若以后想要千分位，把下面两处改回 toLocaleString() 即可。
function animateNumber(element, target, duration = 2000) {
    let start = 0;
    const increment = target / (duration / 16);
    
    function updateNumber() {
        start += increment;
        if (start < target) {
            element.textContent = String(Math.floor(start));
            requestAnimationFrame(updateNumber);
        } else {
            element.textContent = String(target);
        }
    }
    
    updateNumber();
}

// ===== 观察器配置 =====
const observerOptions = {
    root: null,
    rootMargin: '0px',
    threshold: 0.2
};

// ===== 数字动画观察器 =====
const statsObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            const number = entry.target.querySelector('.stat-number');
            if (number) {
                const target = parseInt(number.getAttribute('data-target'));
                animateNumber(number, target);
            }
            statsObserver.unobserve(entry.target);
        }
    });
}, observerOptions);

statNumbers.forEach(stat => {
    statsObserver.observe(stat.parentElement);
});

// ===== 元素淡入动画观察器 =====
const fadeObserver = new IntersectionObserver((entries) => {
    entries.forEach((entry, index) => {
        if (entry.isIntersecting) {
            setTimeout(() => {
                entry.target.classList.add('visible');
            }, index * 150);
            fadeObserver.unobserve(entry.target);
        }
    });
}, observerOptions);

// 观察教程卡片
tutorialCards.forEach((card, index) => {
    card.style.transitionDelay = `${index * 0.1}s`;
    fadeObserver.observe(card);
});

// 观察功能项
featureItems.forEach((item, index) => {
    item.style.transitionDelay = `${index * 0.1}s`;
    fadeObserver.observe(item);
});

productCards.forEach((card, index) => {
    card.style.transitionDelay = `${index * 0.1}s`;
    fadeObserver.observe(card);
});

// .review-card 不纳入观察是刻意的：它没有 opacity:0 的初始隐藏状态，
// 也就没有对应的 .visible 规则，加进来只会白跑一轮 IO 回调。

// ===== 导航链接高亮 =====
const sections = document.querySelectorAll('section[id]');
// 高亮逻辑合并进文件末尾的「滚动统一处理」，避免多个 scroll 监听交替读写造成强制重排

// ===== 鼠标跟随效果（hero 透视倾斜）=====
// 每次 mousemove 都调 getBoundingClientRect() 会强制同步布局，这里改为按帧合并；
// 宽高每帧重新量一次，滚动或布局变化后也不会用到过期坐标。
// 入场动画已改用 translate 属性书写（见 styles.css 的 @keyframes fadeInUp），
// 所以 transform 是空闲的，行内 transform 不会被动画压掉。
const heroContent = document.querySelector('.hero-content');

if (heroContent) {
    let heroX = 0;
    let heroY = 0;

    const applyHeroTilt = rafThrottle(() => {
        const rect = heroContent.getBoundingClientRect();
        const x = (heroX - rect.left) / rect.width - 0.5;
        const y = (heroY - rect.top) / rect.height - 0.5;

        heroContent.style.transform =
            `perspective(1000px) rotateY(${(x * 5).toFixed(2)}deg) rotateX(${(-y * 5).toFixed(2)}deg)`;
    });

    heroContent.addEventListener('mousemove', (e) => {
        heroX = e.clientX;
        heroY = e.clientY;
        applyHeroTilt();
    });

    // 清空行内 transform 交回 CSS，而不是写一个等价的单位矩阵
    heroContent.addEventListener('mouseleave', () => {
        heroContent.style.transform = '';
    });
}

// ===== 卡片 3D 倾斜 =====
// 这里只写 transform；卡片自己的「入场位移 + hover 抬起」已改用独立属性
// translate / scale 承载（见 styles.css 同名规则）。两者是互不干扰的两套属性，
// 所以 hover 抬起不会再被行内 transform 顶掉 —— 在此之前它一直是失效的。
document.querySelectorAll('.tutorial-card, .feature-item, .stat-card, .products-card').forEach(card => {
    let lastX = 0;
    let lastY = 0;

    // 按帧合并：宽高每帧只量一次，且只有当前悬停的那张卡会跑。
    // 相比原先「每次 mousemove 都量一次」，强制同步布局的次数降了一到两个数量级。
    const applyTilt = rafThrottle(() => {
        const rect = card.getBoundingClientRect();
        const x = (lastX - rect.left) / rect.width - 0.5;
        const y = (lastY - rect.top) / rect.height - 0.5;

        // 不再叠加 translateZ(20px)：hover 的 scale:1.02 已经负责「浮起」，
        // 两者叠加会变成约 1.04 的放大。
        card.style.transform =
            `perspective(1000px) rotateY(${(x * 10).toFixed(2)}deg) rotateX(${(-y * 10).toFixed(2)}deg)`;
    });

    card.addEventListener('mousemove', (e) => {
        lastX = e.clientX;
        lastY = e.clientY;
        applyTilt();
    });

    card.addEventListener('mouseleave', () => {
        card.style.transform = '';
    });
});

// ===== 打字机效果 =====
function typeWriter(element, text, speed = 100) {
    let i = 0;
    element.textContent = '';
    
    function type() {
        if (i < text.length) {
            element.textContent += text.charAt(i);
            i++;
            setTimeout(type, speed);
        }
    }
    
    type();
}

// ===== 页面加载动画 =====
window.addEventListener('load', () => {
    document.body.classList.add('loaded');
    
    // 为页面元素添加进入动画
    // 位移用 translate 而不是 transform：写成行内 transform 会常驻元素上，
    // 之后这些子元素自己的 hover / 动画再想用 transform 就会被它顶掉
    // （.hero-badge 的 pulse 动画就曾因此把入场位移整个吃掉）。
    const heroElements = document.querySelectorAll('.hero-content > *');
    heroElements.forEach((el, index) => {
        el.style.opacity = '0';
        el.style.translate = '0 20px';
        
        setTimeout(() => {
            el.style.transition = 'opacity 0.6s ease, translate 0.6s ease';
            el.style.opacity = '1';
            el.style.translate = '0 0';
        }, 200 + index * 150);
    });
});

// ===== 背景光斑：视差滚动 + 鼠标跟随 =====
// 注意：.floating-shape 的 transform 已被 @keyframes float 占用，而 CSS 动画的
// 优先级高于行内样式 —— 往 transform 里写会被动画忽略（旧代码因此从未生效），
// 且用 += 拼接会让 transform 字符串无限增长。这里改写独立的 translate 属性，
// 它与 transform 是两套互不干扰的属性，可以和动画叠加生效。
const floatingShapes = Array.from(document.querySelectorAll('.floating-shape'));

let parallaxY = 0;
let pointerX = window.innerWidth / 2;
let pointerY = window.innerHeight / 2;

function applyShapeOffsets() {
    const centerX = window.innerWidth / 2;
    const centerY = window.innerHeight / 2;

    floatingShapes.forEach((shape, index) => {
        const followSpeed = 0.05 + index * 0.02;
        const parallaxSpeed = 0.2 + index * 0.1;
        // 限制视差位移上限，避免滚到页面底部时光斑被推出视口
        const drift = Math.min(parallaxY * parallaxSpeed, 140);
        const x = (centerX - pointerX) * followSpeed;
        const y = (centerY - pointerY) * followSpeed + drift;

        // 赋值而非 +=：字符串长度恒定，不会随交互次数累积
        shape.style.translate = `${x.toFixed(1)}px ${y.toFixed(1)}px`;
    });
}

// 鼠标跟随按帧合并（滚动驱动的视差在统一的滚动处理里直接调用）
const scheduleShapeUpdate = rafThrottle(applyShapeOffsets);

document.addEventListener('mousemove', (e) => {
    pointerX = e.clientX;
    pointerY = e.clientY;
    scheduleShapeUpdate();
});

// ===== 按钮点击涟漪效果 =====
document.querySelectorAll('.btn').forEach(button => {
    button.addEventListener('click', function(e) {
        const rect = this.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;
        
        const ripple = document.createElement('span');
        ripple.style.cssText = `
            position: absolute;
            background: rgba(255, 255, 255, 0.3);
            border-radius: 50%;
            transform: scale(0);
            animation: ripple 0.6s linear;
            pointer-events: none;
            left: ${x}px;
            top: ${y}px;
            width: 100px;
            height: 100px;
            margin-left: -50px;
            margin-top: -50px;
        `;
        
        this.style.position = 'relative';
        this.style.overflow = 'hidden';
        this.appendChild(ripple);
        
        setTimeout(() => ripple.remove(), 600);
    });
});

// 添加涟漪动画样式
const style = document.createElement('style');
style.textContent = `
    @keyframes ripple {
        to {
            transform: scale(4);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);

// ===== 滚动统一处理 =====
// 原先有 4 个各自独立的 scroll 监听（导航栏样式 / 导航高亮 / 背景光斑视差 /
// 一个包裹着空函数的「假 throttle」），它们交替读写样式会触发强制同步布局。
// 现在合并成一个、按帧合并执行，并把「读取阶段」整体放在「写入阶段」之前。
function handleScrollFrame() {
    // ---- 读取阶段：只读，不碰样式，避免读写交替引发强制重排 ----
    const currentScrollY = window.scrollY;
    let currentSection = '';
    sections.forEach(section => {
        if (currentScrollY >= section.offsetTop - 200) {
            currentSection = section.getAttribute('id');
        }
    });

    // ---- 写入阶段 ----
    navbar.classList.toggle('scrolled', currentScrollY > 50);
    if (backToTop) {
        backToTop.classList.toggle('visible', currentScrollY > 400);
    }
    navLinks.forEach(link => {
        link.classList.toggle('active', link.getAttribute('href') === `#${currentSection}`);
    });

    // 背景光斑视差：已经在 rAF 内，直接执行即可，不必再排一帧
    parallaxY = currentScrollY;
    applyShapeOffsets();
}

window.addEventListener('scroll', rafThrottle(handleScrollFrame));

// ===== 控制台欢迎信息 =====
console.log('%c🚀 90APT车机导航站', 'font-size: 24px; font-weight: bold; color: #667eea;');
console.log('%c欢迎访问！开源免费 · 专业服务 · 持续更新', 'font-size: 14px; color: #764ba2;');