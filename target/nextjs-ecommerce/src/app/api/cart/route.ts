import { NextRequest, NextResponse } from 'next/server';

// Simulated cart storage (in real app, this would be in a database/session)
interface CartItem {
  productId: string;
  quantity: number;
  selectedColor: string;
  selectedSize: string;
}

// Using a simple Map to simulate per-user carts
const carts = new Map<string, CartItem[]>();

// Helper to get user ID from headers (in real app, from auth token)
function getUserId(request: NextRequest): string {
  return request.headers.get('x-user-id') || 'anonymous';
}

export async function GET(request: NextRequest) {
  await new Promise(resolve => setTimeout(resolve, 100));

  const userId = getUserId(request);
  const cart = carts.get(userId) || [];

  return NextResponse.json({
    items: cart,
    itemCount: cart.reduce((sum, item) => sum + item.quantity, 0),
  });
}

export async function POST(request: NextRequest) {
  await new Promise(resolve => setTimeout(resolve, 100));

  const userId = getUserId(request);
  const body = await request.json();
  const { productId, quantity = 1, selectedColor, selectedSize } = body;

  if (!productId) {
    return NextResponse.json(
      { error: 'Product ID is required' },
      { status: 400 }
    );
  }

  const cart = carts.get(userId) || [];

  // Check if item already exists
  const existingIndex = cart.findIndex(
    item => item.productId === productId &&
      item.selectedColor === selectedColor &&
      item.selectedSize === selectedSize
  );

  if (existingIndex >= 0) {
    cart[existingIndex].quantity += quantity;
  } else {
    cart.push({ productId, quantity, selectedColor, selectedSize });
  }

  carts.set(userId, cart);

  return NextResponse.json({
    success: true,
    cart: {
      items: cart,
      itemCount: cart.reduce((sum, item) => sum + item.quantity, 0),
    }
  });
}

export async function PUT(request: NextRequest) {
  await new Promise(resolve => setTimeout(resolve, 100));

  const userId = getUserId(request);
  const body = await request.json();
  const { productId, quantity, selectedColor, selectedSize } = body;

  if (!productId) {
    return NextResponse.json(
      { error: 'Product ID is required' },
      { status: 400 }
    );
  }

  const cart = carts.get(userId) || [];

  const existingIndex = cart.findIndex(
    item => item.productId === productId &&
      item.selectedColor === selectedColor &&
      item.selectedSize === selectedSize
  );

  if (existingIndex >= 0) {
    if (quantity <= 0) {
      cart.splice(existingIndex, 1);
    } else {
      cart[existingIndex].quantity = quantity;
    }
  }

  carts.set(userId, cart);

  return NextResponse.json({
    success: true,
    cart: {
      items: cart,
      itemCount: cart.reduce((sum, item) => sum + item.quantity, 0),
    }
  });
}

export async function DELETE(request: NextRequest) {
  await new Promise(resolve => setTimeout(resolve, 100));

  const userId = getUserId(request);
  const { searchParams } = new URL(request.url);
  const productId = searchParams.get('productId');
  const clearAll = searchParams.get('clearAll');

  if (clearAll === 'true') {
    carts.set(userId, []);
    return NextResponse.json({ success: true, cart: { items: [], itemCount: 0 } });
  }

  if (!productId) {
    return NextResponse.json(
      { error: 'Product ID is required' },
      { status: 400 }
    );
  }

  const cart = carts.get(userId) || [];
  const filtered = cart.filter(item => item.productId !== productId);
  carts.set(userId, filtered);

  return NextResponse.json({
    success: true,
    cart: {
      items: filtered,
      itemCount: filtered.reduce((sum, item) => sum + item.quantity, 0),
    }
  });
}
