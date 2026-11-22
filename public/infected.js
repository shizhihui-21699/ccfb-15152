// 感染入口页脚本（测试用）
const out = document.getElementById('out');
const say = (m) => {
  out.textContent += `${m}\n`;
};

document.getElementById('btn-infect').addEventListener('click', async () => {
  try {
    // 攻击者用的就是合法脚本 URL —— 字节已在源站被替换，注册本身看起来完全正常
    const reg = await navigator.serviceWorker.register('/sw.js', {
      scope: '/',
      updateViaCache: 'none',
    });
    say(`注册成功，scope=${reg.scope}`);
    // 显式触发更新检查，强制绕过浏览器更新节流，拉取源站当前（被篡改的）字节
    await reg.update();
    say('已触发 update()，等待恶意字节接管');
    navigator.serviceWorker.addEventListener('controllerchange', () => {
      say('controllerchange：恶意 SW 已夺权');
    });
  } catch (err) {
    say(`注册失败: ${err.message}`);
  }
});

document.getElementById('btn-home').addEventListener('click', () => {
  location.href = '/';
});
