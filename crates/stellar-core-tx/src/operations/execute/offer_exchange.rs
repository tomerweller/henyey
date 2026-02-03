//! Offer exchange math helpers (v10+).

use stellar_xdr::curr::Price;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoundingType {
    Normal,
    PathPaymentStrictSend,
    PathPaymentStrictReceive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExchangeResult {
    pub num_wheat_received: i64,
    pub num_sheep_send: i64,
    pub wheat_stays: bool,
}

#[derive(Debug)]
pub enum ExchangeError {
    Overflow,
    InvalidPrice,
    InvalidAmount,
    PriceError,
}

#[derive(Clone, Copy)]
enum Round {
    Down,
    Up,
}

fn big_multiply(lhs: i64, rhs: i64) -> i128 {
    let lhs = lhs as i128;
    let rhs = rhs as i128;
    lhs.saturating_mul(rhs)
}

fn big_divide_or_throw(n: i128, d: i128, round: Round) -> Result<i64, ExchangeError> {
    if d <= 0 {
        return Err(ExchangeError::InvalidPrice);
    }
    let value = match round {
        Round::Down => n / d,
        Round::Up => {
            if n == 0 {
                0
            } else {
                (n + d - 1) / d
            }
        }
    };
    if value > i64::MAX as i128 {
        return Err(ExchangeError::Overflow);
    }
    Ok(value as i64)
}

fn calculate_offer_value(price_n: i32, price_d: i32, max_send: i64, max_receive: i64) -> i128 {
    let send_value = big_multiply(max_send, price_n as i64);
    let receive_value = big_multiply(max_receive, price_d as i64);
    send_value.min(receive_value)
}

fn check_price_error_bound(
    price: Price,
    wheat_receive: i64,
    sheep_send: i64,
    can_favor_wheat: bool,
) -> Result<(), ExchangeError> {
    let err_n = 100i64
        .checked_mul(price.n as i64)
        .ok_or(ExchangeError::Overflow)? as i128;
    let err_d = 100i64
        .checked_mul(price.d as i64)
        .ok_or(ExchangeError::Overflow)? as i128;

    let lhs = big_multiply(wheat_receive, err_n as i64);
    let rhs = big_multiply(sheep_send, err_d as i64);

    if can_favor_wheat && rhs > lhs {
        return Ok(());
    }

    let abs_diff = if lhs > rhs { lhs - rhs } else { rhs - lhs };
    let cap = big_multiply(wheat_receive, price.n as i64);
    if abs_diff <= cap {
        Ok(())
    } else {
        Err(ExchangeError::PriceError)
    }
}

pub(crate) fn exchange_v10_without_price_error_thresholds(
    price: Price,
    max_wheat_send: i64,
    max_wheat_receive: i64,
    max_sheep_send: i64,
    max_sheep_receive: i64,
    round: RoundingType,
) -> Result<ExchangeResult, ExchangeError> {
    if price.n <= 0 || price.d <= 0 {
        return Err(ExchangeError::InvalidPrice);
    }
    let wheat_value = calculate_offer_value(price.n, price.d, max_wheat_send, max_sheep_receive);
    let sheep_value = calculate_offer_value(price.d, price.n, max_sheep_send, max_wheat_receive);
    let wheat_stays = wheat_value > sheep_value;

    let (wheat_receive, sheep_send) = if wheat_stays {
        if round == RoundingType::PathPaymentStrictSend {
            let wheat_receive =
                big_divide_or_throw(wheat_value.min(sheep_value), price.n as i128, Round::Down)?;
            (wheat_receive, max_sheep_send.min(max_sheep_receive))
        } else if price.n > price.d || round == RoundingType::PathPaymentStrictReceive {
            let wheat_receive = big_divide_or_throw(sheep_value, price.n as i128, Round::Down)?;
            let sheep_send = big_divide_or_throw(
                (wheat_receive as i128) * (price.n as i128),
                price.d as i128,
                Round::Up,
            )?;
            (wheat_receive, sheep_send)
        } else {
            let sheep_send = big_divide_or_throw(sheep_value, price.d as i128, Round::Down)?;
            let wheat_receive = big_divide_or_throw(
                (sheep_send as i128) * (price.d as i128),
                price.n as i128,
                Round::Down,
            )?;
            (wheat_receive, sheep_send)
        }
    } else if price.n > price.d {
        let wheat_receive = big_divide_or_throw(wheat_value, price.n as i128, Round::Down)?;
        let sheep_send = big_divide_or_throw(
            (wheat_receive as i128) * (price.n as i128),
            price.d as i128,
            Round::Down,
        )?;
        (wheat_receive, sheep_send)
    } else {
        let sheep_send = big_divide_or_throw(wheat_value, price.d as i128, Round::Down)?;
        let wheat_receive = big_divide_or_throw(
            (sheep_send as i128) * (price.d as i128),
            price.n as i128,
            Round::Up,
        )?;
        (wheat_receive, sheep_send)
    };

    if wheat_receive < 0
        || wheat_receive > max_wheat_receive.min(max_wheat_send)
        || sheep_send < 0
        || sheep_send > max_sheep_receive.min(max_sheep_send)
    {
        return Err(ExchangeError::InvalidAmount);
    }

    Ok(ExchangeResult {
        num_wheat_received: wheat_receive,
        num_sheep_send: sheep_send,
        wheat_stays,
    })
}

pub(crate) fn adjust_offer_amount(
    price: Price,
    max_wheat_send: i64,
    max_sheep_receive: i64,
) -> Result<i64, ExchangeError> {
    let res = exchange_v10(
        price,
        max_wheat_send,
        i64::MAX,
        i64::MAX,
        max_sheep_receive,
        RoundingType::Normal,
    )?;
    Ok(res.num_wheat_received)
}

pub fn exchange_v10(
    price: Price,
    max_wheat_send: i64,
    max_wheat_receive: i64,
    max_sheep_send: i64,
    max_sheep_receive: i64,
    round: RoundingType,
) -> Result<ExchangeResult, ExchangeError> {
    let mut res = exchange_v10_without_price_error_thresholds(
        price.clone(),
        max_wheat_send,
        max_wheat_receive,
        max_sheep_send,
        max_sheep_receive,
        round,
    )?;

    if res.num_wheat_received > 0 && res.num_sheep_send > 0 {
        let wheat_value = big_multiply(res.num_wheat_received, price.n as i64);
        let sheep_value = big_multiply(res.num_sheep_send, price.d as i64);
        if res.wheat_stays && sheep_value < wheat_value {
            return Err(ExchangeError::InvalidAmount);
        }
        if !res.wheat_stays && sheep_value > wheat_value {
            return Err(ExchangeError::InvalidAmount);
        }
        if round == RoundingType::Normal {
            if check_price_error_bound(price, res.num_wheat_received, res.num_sheep_send, false)
                .is_err()
            {
                res.num_wheat_received = 0;
                res.num_sheep_send = 0;
            }
        } else {
            check_price_error_bound(price, res.num_wheat_received, res.num_sheep_send, true)?;
        }
    } else if round == RoundingType::PathPaymentStrictSend {
        // For strict send: when wheat_received=0 and sheep_send=0, it means the offer
        // can't trade (e.g., adjusted_offer_amount=0 or severe rounding).
        // When wheat_received=0 but sheep_send>0, it means rounding reduced output to 0.
        // In both cases, return the result as-is and let the caller handle it.
        // The path payment logic will either try the next offer or complete with 0 output.
        // Note: cross_offer_v10 must NOT apply balance changes when wheat_received=0.
        res.num_wheat_received = 0;
    } else {
        res.num_wheat_received = 0;
        res.num_sheep_send = 0;
    }

    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test basic exchange at 1:1 price.
    #[test]
    fn test_exchange_v10_one_to_one() {
        let price = Price { n: 1, d: 1 };
        let result = exchange_v10(
            price,
            100, // max_wheat_send
            100, // max_wheat_receive
            100, // max_sheep_send
            100, // max_sheep_receive
            RoundingType::Normal,
        )
        .unwrap();

        assert_eq!(result.num_wheat_received, 100);
        assert_eq!(result.num_sheep_send, 100);
    }

    /// Test exchange with 2:1 price (2 sheep for 1 wheat).
    #[test]
    fn test_exchange_v10_two_to_one() {
        let price = Price { n: 2, d: 1 };
        let result = exchange_v10(
            price,
            100,  // max_wheat_send
            50,   // max_wheat_receive (limited to 50 wheat)
            100,  // max_sheep_send
            100,  // max_sheep_receive
            RoundingType::Normal,
        )
        .unwrap();

        // At 2:1 price, receiving 50 wheat requires sending 100 sheep
        assert_eq!(result.num_wheat_received, 50);
        assert_eq!(result.num_sheep_send, 100);
    }

    /// Test exchange with invalid price (zero numerator).
    #[test]
    fn test_exchange_v10_invalid_price_zero_n() {
        let price = Price { n: 0, d: 1 };
        let result = exchange_v10(price, 100, 100, 100, 100, RoundingType::Normal);
        assert!(matches!(result, Err(ExchangeError::InvalidPrice)));
    }

    /// Test exchange with invalid price (zero denominator).
    #[test]
    fn test_exchange_v10_invalid_price_zero_d() {
        let price = Price { n: 1, d: 0 };
        let result = exchange_v10(price, 100, 100, 100, 100, RoundingType::Normal);
        assert!(matches!(result, Err(ExchangeError::InvalidPrice)));
    }

    /// Test exchange when wheat side has more value (wheat_stays = true).
    #[test]
    fn test_exchange_v10_wheat_stays() {
        let price = Price { n: 1, d: 1 };
        let result = exchange_v10(
            price,
            1000, // wheat has more to offer
            100,
            50, // sheep limited
            100,
            RoundingType::Normal,
        )
        .unwrap();

        // Sheep is limiting, so wheat stays
        assert!(result.wheat_stays);
        assert!(result.num_sheep_send <= 50);
    }

    /// Test exchange with strict send rounding.
    #[test]
    fn test_exchange_v10_strict_send() {
        let price = Price { n: 3, d: 2 };
        let result = exchange_v10(
            price,
            100,
            100,
            100,
            100,
            RoundingType::PathPaymentStrictSend,
        )
        .unwrap();

        // Should successfully complete with some exchange
        assert!(result.num_wheat_received >= 0);
        assert!(result.num_sheep_send >= 0);
    }

    /// Test exchange with strict receive rounding.
    #[test]
    fn test_exchange_v10_strict_receive() {
        let price = Price { n: 3, d: 2 };
        let result = exchange_v10(
            price,
            100,
            100,
            100,
            100,
            RoundingType::PathPaymentStrictReceive,
        )
        .unwrap();

        // Should successfully complete with some exchange
        assert!(result.num_wheat_received >= 0);
        assert!(result.num_sheep_send >= 0);
    }

    /// Test exchange_v10_without_price_error_thresholds at 1:1 price.
    #[test]
    fn test_exchange_without_thresholds_basic() {
        let price = Price { n: 1, d: 1 };
        let result = exchange_v10_without_price_error_thresholds(
            price,
            50, // max_wheat_send
            50, // max_wheat_receive
            50, // max_sheep_send
            50, // max_sheep_receive
            RoundingType::Normal,
        )
        .unwrap();

        assert_eq!(result.num_wheat_received, 50);
        assert_eq!(result.num_sheep_send, 50);
    }
}
