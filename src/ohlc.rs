use std::collections::HashMap;

use chrono::{DateTime, DurationRound, TimeDelta, Utc};
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
                self.current_tick.replace(Tick::<T>::new(
                    timestamp.duration_trunc(self.period).unwrap(),
                    value,
                ))
            } else {
                current_tick.include(value);
                None
            }
        } else {
            self.current_tick.replace(Tick::<T>::new(
                timestamp.duration_trunc(self.period).unwrap(),
                value,
            ))
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
                .expect("cannot insert a new aggregator even though it doesn't exist")
        };

        // Report to the appopriate aggregator
        if price.is_zero() {
            None
        } else {
            aggregator.report(price, timestamp)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::assert_matches::assert_matches;

    use chrono::{Duration, TimeZone as _, Utc};

    use crate::ohlc::{Aggregator, Tick};

    #[test]
    fn test_tick_include() {
        let mut tick = Tick::new(Utc::now(), 10.0);

        tick.include(15.0);
        assert_matches!(
            tick,
            Tick {
                open: 10.0,
                high: 15.0,
                low: 10.0,
                close: 15.0,
                timestamp: _,
            }
        );

        tick.include(5.0);
        assert_matches!(
            tick,
            Tick {
                open: 10.0,
                high: 15.0,
                low: 5.0,
                close: 5.0,
                timestamp: _,
            }
        );

        tick.include(12.0);
        assert_matches!(
            tick,
            Tick {
                open: 10.0,
                high: 15.0,
                low: 5.0,
                close: 12.0,
                timestamp: _,
            }
        );
    }

    #[test]
    fn test_aggregator_report_first_tick() {
        let mut aggregator = Aggregator::new(Duration::seconds(60));
        let timestamp = Utc.with_ymd_and_hms(2024, 7, 1, 0, 0, 0).unwrap();
        let result = aggregator.report(10.0, timestamp);

        assert!(result.is_none());
    }

    #[test]
    fn test_aggregator_report_within_period() {
        let mut aggregator = Aggregator::new(Duration::seconds(60));
        let start = Utc.with_ymd_and_hms(2024, 7, 1, 0, 0, 0).unwrap();

        aggregator.report(10.0, start);
        let result = aggregator.report(15.0, start + Duration::seconds(30));

        assert!(result.is_none());
        assert_matches!(
            aggregator.current_tick,
            Some(Tick {
                open: 10.0,
                high: 15.0,
                low: 10.0,
                close: 15.0,
                timestamp,
            }) if timestamp == start
        );
    }

    #[test]
    fn test_aggregator_report_new_period() {
        let mut aggregator = Aggregator::new(Duration::seconds(60));
        let start = Utc.with_ymd_and_hms(2024, 7, 1, 0, 0, 0).unwrap();

        aggregator.report(10.0, start);
        let result = aggregator.report(20.0, start + Duration::seconds(70));

        assert_matches!(
            result,
            Some(Tick {
                open: 10.0,
                high: 10.0,
                low: 10.0,
                close: 10.0,
                timestamp,
            }) if timestamp == start
        );
    }

    #[test]
    fn test_aggregator_report_multiple_periods() {
        let mut aggregator = Aggregator::new(Duration::seconds(60));
        let start = Utc.with_ymd_and_hms(2024, 7, 1, 0, 0, 0).unwrap();

        aggregator.report(10.0, start);
        let result = aggregator.report(20.0, start + Duration::seconds(150));

        assert_matches!(
            result,
            Some(Tick {
                open: 10.0,
                high: 10.0,
                low: 10.0,
                close: 10.0,
                timestamp,
            }) if timestamp == start
        );
    }

    #[test]
    fn test_aggregator_report_out_of_order() {
        let mut aggregator = Aggregator::new(Duration::seconds(60));
        let start = Utc.with_ymd_and_hms(2024, 7, 1, 0, 0, 0).unwrap();

        aggregator.report(10.0, start);
        aggregator.report(15.0, start - Duration::seconds(30));

        assert_eq!(aggregator.last_timestamp, Some(start));
        // Note: We can't easily test the warning log here without additional setup
    }
}
