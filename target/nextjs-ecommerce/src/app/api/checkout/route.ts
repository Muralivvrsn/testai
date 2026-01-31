import { NextRequest, NextResponse } from 'next/server';

// Simulated order storage
interface Order {
  id: string;
  userId: string;
  items: OrderItem[];
  shipping: ShippingInfo;
  payment: PaymentInfo;
  totals: OrderTotals;
  status: 'pending' | 'processing' | 'shipped' | 'delivered' | 'cancelled';
  createdAt: Date;
  updatedAt: Date;
}

interface OrderItem {
  productId: string;
  name: string;
  price: number;
  quantity: number;
  selectedColor?: string;
  selectedSize?: string;
}

interface ShippingInfo {
  firstName: string;
  lastName: string;
  email: string;
  phone: string;
  address: string;
  city: string;
  state: string;
  zip: string;
  country: string;
}

interface PaymentInfo {
  method: 'card' | 'paypal' | 'applepay';
  last4?: string;
  brand?: string;
}

interface OrderTotals {
  subtotal: number;
  shipping: number;
  tax: number;
  discount: number;
  total: number;
}

const orders: Order[] = [];

// Simulated promo codes
const promoCodes: Record<string, { type: 'percent' | 'fixed' | 'shipping'; value: number }> = {
  'SAVE10': { type: 'percent', value: 10 },
  'SAVE20': { type: 'percent', value: 20 },
  'FLAT50': { type: 'fixed', value: 50 },
  'FREESHIP': { type: 'shipping', value: 100 },
};

function generateOrderId(): string {
  return 'ORD-' + Date.now().toString(36).toUpperCase() + '-' + Math.random().toString(36).substring(2, 6).toUpperCase();
}

function getUserId(request: NextRequest): string {
  return request.headers.get('x-user-id') || 'anonymous';
}

export async function POST(request: NextRequest) {
  await new Promise(resolve => setTimeout(resolve, 1000)); // Simulate payment processing

  const body = await request.json();
  const { action } = body;

  switch (action) {
    case 'validate-promo': {
      const { code, subtotal } = body;

      if (!code) {
        return NextResponse.json(
          { error: 'Promo code is required' },
          { status: 400 }
        );
      }

      const promo = promoCodes[code.toUpperCase()];

      if (!promo) {
        return NextResponse.json(
          { error: 'Invalid promo code' },
          { status: 400 }
        );
      }

      let discount = 0;
      let message = '';

      switch (promo.type) {
        case 'percent':
          discount = (subtotal || 0) * (promo.value / 100);
          message = `${promo.value}% off applied!`;
          break;
        case 'fixed':
          discount = promo.value;
          message = `$${promo.value} off applied!`;
          break;
        case 'shipping':
          discount = 9.99; // Standard shipping cost
          message = 'Free shipping applied!';
          break;
      }

      return NextResponse.json({
        valid: true,
        discount: Math.round(discount * 100) / 100,
        message,
      });
    }

    case 'calculate-totals': {
      const { items, promoCode } = body;

      if (!items || !Array.isArray(items) || items.length === 0) {
        return NextResponse.json(
          { error: 'Cart items are required' },
          { status: 400 }
        );
      }

      const subtotal = items.reduce(
        (sum: number, item: { price: number; quantity: number }) =>
          sum + item.price * item.quantity,
        0
      );

      const shipping = subtotal >= 100 ? 0 : 9.99;
      const taxRate = 0.08;
      const tax = subtotal * taxRate;

      let discount = 0;
      if (promoCode) {
        const promo = promoCodes[promoCode.toUpperCase()];
        if (promo) {
          switch (promo.type) {
            case 'percent':
              discount = subtotal * (promo.value / 100);
              break;
            case 'fixed':
              discount = Math.min(promo.value, subtotal);
              break;
            case 'shipping':
              discount = shipping;
              break;
          }
        }
      }

      const total = subtotal + shipping + tax - discount;

      return NextResponse.json({
        subtotal: Math.round(subtotal * 100) / 100,
        shipping: Math.round(shipping * 100) / 100,
        tax: Math.round(tax * 100) / 100,
        discount: Math.round(discount * 100) / 100,
        total: Math.round(total * 100) / 100,
      });
    }

    case 'validate-shipping': {
      const { shipping } = body;

      const errors: Record<string, string> = {};

      if (!shipping.firstName) errors.firstName = 'First name is required';
      if (!shipping.lastName) errors.lastName = 'Last name is required';
      if (!shipping.email) errors.email = 'Email is required';
      else if (!/\S+@\S+\.\S+/.test(shipping.email)) errors.email = 'Invalid email format';
      if (!shipping.phone) errors.phone = 'Phone is required';
      if (!shipping.address) errors.address = 'Address is required';
      if (!shipping.city) errors.city = 'City is required';
      if (!shipping.state) errors.state = 'State is required';
      if (!shipping.zip) errors.zip = 'ZIP code is required';
      else if (!/^\d{5}(-\d{4})?$/.test(shipping.zip)) errors.zip = 'Invalid ZIP code';

      if (Object.keys(errors).length > 0) {
        return NextResponse.json({ valid: false, errors }, { status: 400 });
      }

      return NextResponse.json({ valid: true });
    }

    case 'process-payment': {
      const { items, shipping, payment, totals, promoCode } = body;

      // Validate required fields
      if (!items || items.length === 0) {
        return NextResponse.json(
          { error: 'Cart is empty' },
          { status: 400 }
        );
      }

      if (!shipping) {
        return NextResponse.json(
          { error: 'Shipping information is required' },
          { status: 400 }
        );
      }

      if (!payment) {
        return NextResponse.json(
          { error: 'Payment information is required' },
          { status: 400 }
        );
      }

      // Validate card details if using card payment
      if (payment.method === 'card') {
        const cardNumber = payment.cardNumber?.replace(/\s/g, '');
        if (!cardNumber || cardNumber.length !== 16) {
          return NextResponse.json(
            { error: 'Invalid card number' },
            { status: 400 }
          );
        }
        if (!payment.expiry || !/^\d{2}\/\d{2}$/.test(payment.expiry)) {
          return NextResponse.json(
            { error: 'Invalid expiry date' },
            { status: 400 }
          );
        }
        if (!payment.cvv || payment.cvv.length < 3) {
          return NextResponse.json(
            { error: 'Invalid CVV' },
            { status: 400 }
          );
        }

        // Simulate card decline for specific test cards
        if (cardNumber === '4000000000000002') {
          return NextResponse.json(
            { error: 'Card declined. Please try a different card.' },
            { status: 402 }
          );
        }
      }

      // Simulate longer processing for payment
      await new Promise(resolve => setTimeout(resolve, 1500));

      // Create order
      const userId = getUserId(request);
      const orderId = generateOrderId();

      const order: Order = {
        id: orderId,
        userId,
        items: items.map((item: any) => ({
          productId: item.productId,
          name: item.name,
          price: item.price,
          quantity: item.quantity,
          selectedColor: item.selectedColor,
          selectedSize: item.selectedSize,
        })),
        shipping,
        payment: {
          method: payment.method,
          last4: payment.method === 'card' ? payment.cardNumber?.slice(-4) : undefined,
          brand: payment.method === 'card' ? 'Visa' : undefined,
        },
        totals: totals || {
          subtotal: items.reduce((sum: number, item: any) => sum + item.price * item.quantity, 0),
          shipping: 9.99,
          tax: 0,
          discount: 0,
          total: 0,
        },
        status: 'pending',
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      orders.push(order);

      return NextResponse.json({
        success: true,
        orderId,
        message: 'Order placed successfully!',
        order: {
          id: order.id,
          status: order.status,
          totals: order.totals,
          estimatedDelivery: new Date(Date.now() + 5 * 24 * 60 * 60 * 1000).toISOString(),
        },
      });
    }

    default:
      return NextResponse.json(
        { error: 'Invalid action' },
        { status: 400 }
      );
  }
}

export async function GET(request: NextRequest) {
  const userId = getUserId(request);
  const { searchParams } = new URL(request.url);
  const orderId = searchParams.get('orderId');

  if (orderId) {
    const order = orders.find(o => o.id === orderId && o.userId === userId);

    if (!order) {
      return NextResponse.json(
        { error: 'Order not found' },
        { status: 404 }
      );
    }

    return NextResponse.json({ order });
  }

  // Return all orders for user
  const userOrders = orders
    .filter(o => o.userId === userId)
    .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());

  return NextResponse.json({ orders: userOrders });
}
