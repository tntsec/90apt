// ===== DOM 元素 =====
const navbar = document.querySelector('.navbar');
const hamburger = document.querySelector('.hamburger');
const navMenu = document.querySelector('.nav-menu');
const navLinks = document.querySelectorAll('.nav-link');
const statNumbers = document.querySelectorAll('.stat-number');
const tutorialCards = document.querySelectorAll('.tutorial-card');
const featureItems = document.querySelectorAll('.feature-item');

// ===== 导航栏滚动效果 =====
let lastScrollY = window.scrollY;

window.addEventListener('scroll', () => {
    const currentScrollY = window.scrollY;
    
    // 添加/移除滚动样式
    if (currentScrollY > 50) {
        navbar.classList.add('scrolled');
    } else {
        navbar.classList.remove('scrolled');
    }
    
    lastScrollY = currentScrollY;
});

// ===== 移动端菜单切换 =====
hamburger.addEventListener('click', () => {
    hamburger.classList.toggle('active');
    navMenu.classList.toggle('active');
    document.body.style.overflow = navMenu.classList.contains('active') ? 'hidden' : '';
});

// 点击链接关闭菜单
navLinks.forEach(link => {
    link.addEventListener('click', () => {
        hamburger.classList.remove('active');
        navMenu.classList.remove('active');
        document.body.style.overflow = '';
    });
});

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
function animateNumber(element, target, duration = 2000) {
    let start = 0;
    const increment = target / (duration / 16);
    
    function updateNumber() {
        start += increment;
        if (start < target) {
            element.textContent = Math.floor(start).toLocaleString();
            requestAnimationFrame(updateNumber);
        } else {
            element.textContent = target.toLocaleString();
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

// ===== 导航链接高亮 =====
const sections = document.querySelectorAll('section[id]');

window.addEventListener('scroll', () => {
    let current = '';
    
    sections.forEach(section => {
        const sectionTop = section.offsetTop;
        const sectionHeight = section.clientHeight;
        
        if (window.scrollY >= sectionTop - 200) {
            current = section.getAttribute('id');
        }
    });
    
    navLinks.forEach(link => {
        link.classList.remove('active');
        if (link.getAttribute('href') === `#${current}`) {
            link.classList.add('active');
        }
    });
});

// ===== 鼠标跟随效果 =====
const heroContent = document.querySelector('.hero-content');

if (heroContent) {
    heroContent.addEventListener('mousemove', (e) => {
        const rect = heroContent.getBoundingClientRect();
        const x = (e.clientX - rect.left) / rect.width - 0.5;
        const y = (e.clientY - rect.top) / rect.height - 0.5;
        
        heroContent.style.transform = `perspective(1000px) rotateY(${x * 5}deg) rotateX(${-y * 5}deg)`;
    });
    
    heroContent.addEventListener('mouseleave', () => {
        heroContent.style.transform = 'perspective(1000px) rotateY(0deg) rotateX(0deg)';
    });
}

// ===== 卡片3D效果 =====
document.querySelectorAll('.tutorial-card, .feature-item, .stat-card').forEach(card => {
    card.addEventListener('mousemove', (e) => {
        const rect = card.getBoundingClientRect();
        const x = (e.clientX - rect.left) / rect.width - 0.5;
        const y = (e.clientY - rect.top) / rect.height - 0.5;
        
        card.style.transform = `perspective(1000px) rotateY(${x * 10}deg) rotateX(${-y * 10}deg) translateZ(20px)`;
    });
    
    card.addEventListener('mouseleave', () => {
        card.style.transform = 'perspective(1000px) rotateY(0deg) rotateX(0deg) translateZ(0)';
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
    const heroElements = document.querySelectorAll('.hero-content > *');
    heroElements.forEach((el, index) => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(20px)';
        
        setTimeout(() => {
            el.style.transition = 'all 0.6s ease';
            el.style.opacity = '1';
            el.style.transform = 'translateY(0)';
        }, 200 + index * 150);
    });
});

// ===== 视差滚动效果 =====
window.addEventListener('scroll', () => {
    const scrolled = window.pageYOffset;
    
    // 浮动形状的视差效果
    document.querySelectorAll('.floating-shape').forEach((shape, index) => {
        const speed = 0.2 + (index * 0.1);
        shape.style.transform = `translateY(${scrolled * speed}px)`;
    });
});

// ===== 鼠标位置追踪 =====
let mouseX = 0;
let mouseY = 0;

document.addEventListener('mousemove', (e) => {
    mouseX = e.clientX;
    mouseY = e.clientY;
    
    // 为背景形状添加鼠标交互
    document.querySelectorAll('.floating-shape').forEach((shape, index) => {
        const speed = 0.05 + (index * 0.02);
        const x = (window.innerWidth / 2 - mouseX) * speed;
        const y = (window.innerHeight / 2 - mouseY) * speed;
        
        shape.style.transform += ` translate(${x}px, ${y}px)`;
    });
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

// ===== 性能优化：节流函数 =====
function throttle(func, limit) {
    let inThrottle;
    return function() {
        const args = arguments;
        const context = this;
        if (!inThrottle) {
            func.apply(context, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

// 优化滚动事件监听
window.addEventListener('scroll', throttle(() => {
    // 滚动时的其他优化处理
}, 100));

// ===== 控制台欢迎信息 =====
console.log('%c🚀 90APT车机导航站', 'font-size: 24px; font-weight: bold; color: #667eea;');
console.log('%c欢迎访问！开源免费 · 专业服务 · 持续更新', 'font-size: 14px; color: #764ba2;');