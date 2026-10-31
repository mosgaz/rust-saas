use leptos::prelude::*;
use std::collections::HashMap;
use std::time::{Duration, Instant};

const TTL: Duration = Duration::from_secs(30);

/// Клиентский кэш разрешений (permissions) с TTL 30 секунд.
/// Используется для уменьшения количества запросов к серверной функции `my_permissions`
/// при навигации между страницами и после мутаций (assign/remove/change role).
#[derive(Clone)]
pub struct PermsCache {
    map: RwSignal<HashMap<String, (Instant, Vec<(String, String)>)>>,
}

impl PermsCache {
    pub fn new() -> Self {
        Self {
            map: RwSignal::new(HashMap::new()),
        }
    }

    /// Возвращает закэшированные разрешения для `domain`, если они валидны (TTL < 30s).
    /// В противном случае вызывает `fetch_fn`, кэширует результат и возвращает его.
    pub async fn get_or_fetch<F, Fut>(&self, domain: String, fetch_fn: F) -> Vec<(String, String)>
    where
        F: FnOnce(String) -> Fut,
        Fut: std::future::Future<Output = Vec<(String, String)>>,
    {
        // Проверяем кэш без создания реактивных зависимостей (untracked),
        // чтобы чтение не триггерило перерисовку само по себе.
        let cached = self.map.with_untracked(|m| {
            m.get(&domain).and_then(|(instant, perms)| {
                if instant.elapsed() < TTL {
                    Some(perms.clone())
                } else {
                    None
                }
            })
        });

        if let Some(perms) = cached {
            return perms;
        }

        // Кэш отсутствует или устарел — выполняем запрос
        let perms = fetch_fn(domain.clone()).await;

        // Обновляем кэш
        self.map.update(|m| {
            m.insert(domain, (Instant::now(), perms.clone()));
        });

        perms
    }

    /// Инвалидирует кэш для конкретного домена (вызывается после мутаций:
    /// assign_role, remove_role, change_role, create_role, update_role, delete_role).
    pub fn invalidate(&self, domain: &str) {
        self.map.update(|m| {
            m.remove(domain);
        });
    }

    /// Полная очистка кэша (например, при логауте или смене пользователя).
    pub fn invalidate_all(&self) {
        self.map.update(|m| {
            m.clear();
        });
    }
}