use std::collections::HashMap;

use chrono::{DateTime, TimeDelta, Utc};
use log::warn;
use num_traits::Zero;

#[derive(Debug)]
pub struct Tick<T = f64> {
    pub timestamp: DateTime<Utc>,
    pub open: T,
    pub high: T,
    pub low: T,
    pub close: T,
}

impl<T: Copy + PartialOrd> Tick<T> {
    fn new(timestamp: DateTime<Utc>, open: T) -> Self {
        Tick {
            timestamp,
            open,
            high: open,
            low: open,
            close: open,
        }
    }

    fn include(&mut self, value: T) {
        if value > self.high {
            self.high = value;
        }

        if value < self.low {
            self.low = value;
        }
        self.close = value;
    }
}

#[derive(Debug)]
struct Aggregator<T = f64> {
    period: TimeDelta,
    last_timestamp: Option<DateTime<Utc>>,
    current_tick: Option<Tick<T>>,
}

impl<T: Copy + PartialOrd> Aggregator<T> {
    fn new(period: TimeDelta) -> Aggregator<T> {
        Aggregator {
            period,
            last_timestamp: None,
            current_tick: None,
        }
    }

    fn report(&mut self, value: T, timestamp: DateTime<Utc>) -> Option<Tick<T>> {
        // `last_timestamp` is used only for this warning
        if self
            .last_timestamp
            .is_some_and(|last_timestamp| timestamp < last_timestamp)
        {
            warn!(last_timestamp:serde = self.last_timestamp, timestamp:serde; "Timestamps were reported out of order");
        } else {
            let _ = self.last_timestamp.insert(timestamp);
        }

        if let Some(ref mut current_tick) = &mut self.current_tick {
            if timestamp > current_tick.timestamp + self.period {
                // Create a new tick
                let time_since = timestamp - current_tick.timestamp;
                let ticks_since =
                    time_since.num_nanoseconds().unwrap() / self.period.num_nanoseconds().unwrap();
                let new_tick_start = current_tick.timestamp + self.period * (ticks_since as i32);
                self.current_tick
                    .replace(Tick::<T>::new(new_tick_start, value))
            } else {
                current_tick.include(value);
                None
            }
        } else {
            self.current_tick.replace(Tick::<T>::new(timestamp, value))
        }
    }
}

pub struct MetaAggregator<T = f64> {
    period: TimeDelta,
    aggregators: HashMap<String, Aggregator<T>>,
}

impl<T: Copy + std::fmt::Debug + PartialOrd + Zero> MetaAggregator<T> {
    pub fn new(period: TimeDelta) -> MetaAggregator<T> {
        MetaAggregator {
            period,
            aggregators: HashMap::<String, Aggregator<T>>::default(),
        }
    }

    pub fn report(&mut self, symbol: &str, price: T, timestamp: DateTime<Utc>) -> Option<Tick<T>> {
        // Get the aggregator or create one if it doesn't exists
        let aggregator = if self.aggregators.contains_key(symbol) {
            self.aggregators.get_mut(symbol).unwrap()
        } else {
            if !price.is_zero() {
                warn!(symbol; "A quote update about an unknown symbol was reported");
            }

            let new_aggregator = Aggregator::new(self.period);
            self.aggregators
                .try_insert(symbol.to_string(), new_aggregator)
                .expect("cannot insert an aggregator even though it doesn't exist")
        };

        // Report to the appopriate aggregator
        if price.is_zero() {
            None
        } else {
            aggregator.report(price, timestamp)
        }
    }
}
