// Подключение к сокету
const socket = io('http://localhost:5000'); // Убедитесь, что адрес вашего сервера указан правильно





// Функция для отображения уведомлений о входящем звонке
function showIncomingCallNotification(callerId) {
    const notification = document.createElement('div');
    notification.id = 'call-notification';
    notification.style.position = 'fixed';
    notification.style.top = '10px';
    notification.style.right = '10px';
    notification.style.padding = '20px';
    notification.style.backgroundColor = 'rgba(0, 0, 0, 0.8)';
    notification.style.color = 'white';
    notification.innerHTML = `
        <h5>Входящий звонок от ${callerId}</h5>
        <button id="accept-call">Принять</button>
        <button id="decline-call">Отклонить</button>
    `;
    document.body.appendChild(notification);

    document.getElementById('accept-call').onclick = () => {
        handleCallAccept(callerId);
        document.body.removeChild(notification);
    };

    document.getElementById('decline-call').onclick = () => {
        handleCallDecline(callerId);
        document.body.removeChild(notification);
    };
}

// Обработка входящего вызова
socket.on('incoming-call', (data) => {
    showIncomingCallNotification(data.callerId);
});

// Логика для принятия вызова
async function handleCallAccept(callerId) {
    currentCallRecipientId = callerId;
    alert(`Вы приняли звонок от ${callerId}`);
    await initiateVideoCall(callerId); 
}

// Логика для отклонения вызова
function handleCallDecline(callerId) {
    alert(`Вы отклонили звонок от ${callerId}`);
    socket.emit('call-declined', { callerId });
}

// Функция для инициации видеозвонка
async function initiateVideoCall(userId) {
    try {
        currentStream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
        // Отправка события начала звонка на сервер
        socket.emit('start-call', { userId });

        // Отображение интерфейса звонка
        document.getElementById('callRecipient').innerText = `Пользователь ${userId}`;
        document.getElementById('callInterface').style.display = 'block';

        // Настройка видеоэлемента (при наличии на экране)
        const videoElement = document.getElementById('localVideo');
        videoElement.srcObject = currentStream;

        // Обработка таймера для пропущенного звонка
        callTimer = setTimeout(() => handleMissedCall(userId), 300000); // 5 минут
    } catch (error) {
        console.error('Ошибка инициации видеозвонка:', error);
        alert(error.message);
    }
}

// Обработка пропущенного звонка
async function handleMissedCall(userId) {
    alert(`Звонок с пользователем ${userId} не был завершен. Он помечен как пропущенный.`);
    await markAsMissedCall(userId);
    resetCallInterface();
}

// Пометка звонка как пропущенного
async function markAsMissedCall(userId) {
    try {
        const response = await fetch(`/api/mark-missed-call/${userId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ status: 'missed' })
        });
        if (!response.ok) {
            console.error('Ошибка при пометке звонка как пропущенного:', response.statusText);
        }
    } catch (error) {
        console.error('Ошибка при пометке звонка:', error);
    }
}

// Завершение звонка
document.getElementById('endCallButton').addEventListener('click', () => {
    alert(`Звонок с пользователем ${currentCallRecipientId} завершен.`);
    resetCallInterface();
});

// Сброс интерфейса звонка
function resetCallInterface() {
    document.getElementById('callInterface').style.display = 'none'; 

    // Остановка потоков
    if (currentStream) {
        currentStream.getTracks().forEach(track => track.stop());
    }

    if (callTimer) {
        clearTimeout(callTimer);
        callTimer = null;
    }

    currentCallRecipientId = null; // Сброс ID текущего звонка
}

// Отключение микрофона
document.getElementById('muteButton').addEventListener('change', (event) => {
    if (currentStream) {
        currentStream.getAudioTracks().forEach(track => {
            track.enabled = !event.target.checked;
        });
    }
});

// Отключение камеры
document.getElementById('cameraButton').addEventListener('change', (event) => {
    if (currentStream) {
        currentStream.getVideoTracks().forEach(track => {
            track.enabled = !event.target.checked;
        });
    }
});

// Обработка выходящего вызова
async function makeCall(userId) {
    await initiateVideoCall(userId);
}

// Завершение обработки вызова
socket.on('call-ended', data => {
    alert(`Звонок с ${data.callerId} завершён.`);
    resetCallInterface();
});

// Логика для получения истории звонков
async function loadCallHistory() {
    try {
        const response = await fetch('/api/calls');
        const calls = await response.json();
        
        const callHistoryList = document.getElementById('callHistoryList');
        callHistoryList.innerHTML = '';

        calls.forEach(call => {
            const listItem = document.createElement('li');
            listItem.innerHTML = `
                <span>Звонок с ${call.withUser.username}, Дата: ${new Date(call.createdAt).toLocaleString()}</span>
            `;
            callHistoryList.appendChild(listItem);
        });
    } catch (error) {
        console.error('Ошибка при загрузке истории звонков:', error);
    }
}

// Логика для получения списка друзей
async function loadFriends() {
    try {
        const userId = 'YOUR_USER_ID'; // Замените на текущий ID пользователя, когда он будет доступен
        const response = await fetch(`/api/friends/${userId}`);
        const friendsList = await response.json();

        const friendsContainer = document.getElementById('friendsList');
        friendsContainer.innerHTML = ''; // Очистка текущего списка

        friendsList.forEach(friend => {
            const listItem = document.createElement('li');
            listItem.innerText = `${friend.username}`; // Предположим, что поле username доступно
            listItem.onclick = () => makeCall(friend.id); // Начать звонок при клике на друга
            friendsContainer.appendChild(listItem);
        });
    } catch (error) {
        console.error('Ошибка при загрузке списка друзей:', error);
    }
}

// Загрузка данных при загрузке страницы
window.onload = async () => {
    await loadCallHistory();
    await loadFriends(); // Загружаем список друзей
};