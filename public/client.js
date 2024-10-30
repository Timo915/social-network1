// public/client.js


function acceptRequest(requestId, username) {
    fetch(`/accept-request/${requestId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ accept: true, username: username }), // Передаем username
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert('Запрос принят.');
            location.reload(); // Обновляем страницу, чтобы отобразить изменения
        } else {
            alert('Ошибка при принятии запроса.');
        }
    })
    .catch(error => {
        console.error('Ошибка:', error);
        alert('Не удалось принять запрос. Попробуйте позже.');
    });
}